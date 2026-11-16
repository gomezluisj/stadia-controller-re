#!/usr/bin/env python3
"""nor_slice_inspect.py - Offline inspector & partition carver for Stadia Controller NOR dumps.

Maps any NOR dump slice (e.g. a surgical low 256 KiB capture covering 0x000000..0x03ffff,
a Bootloader B capture 0x820000..0x83ffff, a Slot B header sample, or a full 16 MiB dump)
against the 13-partition flash layout recovered from bruce 337784 (0x600740e2..0x60074580)
and gotham 316382 (0x608af764..0x608afade), plus Sector 0 FCB.

Integrates tools/ivt_csf_inspect.py (FCB/Boot IVT/Slot header inspection) and
tools/kvs_parse.py (CRC-16 KVS parsing across id=9 User KVS, id=5 Factory KVS, and
id=4 Bootloader KVS). All processing is offline and read-only. By default, sensitive
key/device identifiers are redacted in printed/JSON reports (override with --no-redact).
"""

import argparse
import contextlib
from dataclasses import asdict
import hashlib
import io
import json
import os
import struct
import sys
import tempfile

_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)

import ivt_csf_inspect
import kvs_parse

NOR_XIP_BASE = 0x60000000
NOR_TOTAL_SIZE = 0x01000000  # 16 MiB (4,096 x 4 KiB sectors)
SECTOR_SIZE = 0x1000

# Complete 16 MiB layout: Sector 0 (FCB) + 13 descriptors registered in board+0x4378.
# Format: (name, part_id, phys_offset, size_bytes, kvs_flags, sensitive_default, role)
NOR_PARTITIONS = (
    (
        "fcb",
        None,
        0x000000,
        0x001000,
        (0, 0),
        False,
        "FlexSPI Configuration Block ('FCFB', sector 0x000)",
    ),
    (
        "boot_ivt",
        0x12,
        0x001000,
        0x001000,
        (0, 0),
        False,
        "Boot IVT + boot_data read by NXP Mask ROM (sector 0x001)",
    ),
    (
        "crash_log_b",
        0x07,
        0x002000,
        0x002000,
        (0, 0),
        False,
        "Secondary crash / bug report store below 0x60006000 write window (sectors 0x002..0x003)",
    ),
    (
        "reserved_low",
        0x0A,
        0x004000,
        0x002000,
        (0, 0),
        False,
        "Protected low partition below 0x60006000 write window (sectors 0x004..0x005)",
    ),
    (
        "bug_reports",
        0x08,
        0x006000,
        0x022000,
        (0, 0),
        True,
        "Primary bug report / crash tombstone store, transfer_bug_report RPC (sectors 0x006..0x027)",
    ),
    (
        "user_kvs",
        0x09,
        0x028000,
        0x008000,
        (1, 0),
        True,
        "User / Runtime KVS, erased on FactoryReset (sectors 0x028..0x02f)",
    ),
    (
        "bt_nvram",
        0x0B,
        0x030000,
        0x004000,
        (0, 0),
        True,
        "Bluetooth bond / remote device NVRAM, erased on FactoryReset (sectors 0x030..0x033)",
    ),
    (
        "aux_data_17",
        0x11,
        0x034000,
        0x004000,
        (0, 0),
        True,
        "Auxiliary partition id=17 (sectors 0x034..0x037)",
    ),
    (
        "factory_kvs",
        0x05,
        0x038000,
        0x004000,
        (1, 1),
        True,
        "Factory / Persistent KVS, survives FactoryReset (sectors 0x038..0x03b)",
    ),
    (
        "bootloader_kvs",
        0x04,
        0x03C000,
        0x004000,
        (1, 1),
        False,
        "Bootloader metadata KVS: AppAMeta/AppBMeta/RecoveryMeta/Bookkeep* (sectors 0x03c..0x03f)",
    ),
    (
        "app_slot_a",
        0x01,
        0x040000,
        0x7C0000,
        (0, 0),
        False,
        "Application Slot A: bruce or gotham (sectors 0x040..0x7ff)",
    ),
    (
        "bootloader_a",
        0x03,
        0x800000,
        0x020000,
        (0, 0),
        False,
        "Bootloader Slot A: zatanna (sectors 0x800..0x81f)",
    ),
    (
        "bootloader_b",
        0x13,
        0x820000,
        0x020000,
        (0, 0),
        False,
        "Bootloader Slot B (sectors 0x820..0x83f; id=4 in zatanna)",
    ),
    (
        "app_slot_b",
        0x02,
        0x840000,
        0x7C0000,
        (0, 0),
        False,
        "Application Slot B: factory gotham (sectors 0x840..0xfff)",
    ),
)

_SENSITIVE_KEY_TOKENS = (
    "udn",
    "uuid",
    "serial",
    "mac",
    "key",
    "secret",
    "token",
    "pass",
    "psk",
    "ssid",
    "auth",
    "cred",
    "ltk",
    "csrk",
    "irk",
    "cert",
    "clientid",
    "cloudid",
    "androidid",
)


def normalize_nor_offset(val):
    """Accept physical NOR offset (0x0..0xffffff) or XIP address (0x60000000..0x60ffffff)."""
    phys = val - NOR_XIP_BASE if val >= NOR_XIP_BASE else val
    if phys < 0 or phys >= NOR_TOTAL_SIZE:
        raise ValueError(
            f"base offset 0x{val:08x} maps outside 16 MiB NOR range [0x000000, 0xffffff]"
        )
    return phys


def _is_sensitive_key(key_name):
    low = (key_name or "").lower()
    return any(tok in low for tok in _SENSITIVE_KEY_TOKENS)


def _sector_stats(blob):
    """Count erased (all 0xFF), zeroed (all 0x00), and populated 4 KiB slices."""
    total_bytes = len(blob)
    non_ff = sum(1 for b in blob if b != 0xFF)
    erased_4k = 0
    zero_4k = 0
    active_4k = 0
    chunks = 0
    for off in range(0, total_bytes, SECTOR_SIZE):
        chunk = blob[off : off + SECTOR_SIZE]
        chunks += 1
        uniq = set(chunk)
        if uniq == {0xFF}:
            erased_4k += 1
        elif uniq == {0x00}:
            zero_4k += 1
        else:
            active_4k += 1
    populated_16b = sum(
        1 for off in range(0, total_bytes, 16) if blob[off : off + 16] != b"\xff" * 16
    )
    return {
        "bytes": total_bytes,
        "non_ff_bytes": non_ff,
        "erased_only": non_ff == 0,
        "chunks_4k": chunks,
        "erased_4k": erased_4k,
        "zero_4k": zero_4k,
        "active_4k": active_4k,
        "populated_16b_blocks": populated_16b,
    }


def parse_fcb(buf, off=0):
    """Parse an i.MX RT106x FlexSPI NOR Configuration Block ('FCFB') header."""
    if off < 0 or off + 0x200 > len(buf):
        return None
    if buf[off : off + 4] != b"FCFB":
        return None
    version = struct.unpack_from("<I", buf, off + 0x04)[0]
    read_sample_clk_src = buf[off + 0x0C]
    cs_hold_time = buf[off + 0x0D]
    cs_setup_time = buf[off + 0x0E]
    controller_misc_option = struct.unpack_from("<I", buf, off + 0x40)[0]
    device_type = buf[off + 0x44]
    sflash_pad_type = buf[off + 0x45]
    serial_clk_freq = buf[off + 0x46]
    sflash_a1_size = struct.unpack_from("<I", buf, off + 0x50)[0]
    lut_words = struct.unpack_from("<64I", buf, off + 0x80)
    nonzero_lut = sum(1 for w in lut_words if w != 0)
    page_size = struct.unpack_from("<I", buf, off + 0x1C0)[0]
    sector_size = struct.unpack_from("<I", buf, off + 0x1C4)[0]
    return {
        "magic": "FCFB",
        "version": version,
        "read_sample_clk_src": read_sample_clk_src,
        "cs_hold_time": cs_hold_time,
        "cs_setup_time": cs_setup_time,
        "controller_misc_option": controller_misc_option,
        "device_type": device_type,
        "sflash_pad_type": sflash_pad_type,
        "serial_clk_freq": serial_clk_freq,
        "sflash_a1_size": sflash_a1_size,
        "nonzero_lut_words": nonzero_lut,
        "page_size": page_size,
        "sector_size": sector_size,
    }


def _inspect_boot_ivt(part_bytes, part_phys):
    """Inspect Boot IVT at physical 0x001000 and check the IVT.self 0x60001000 vs 0x60001020 question."""
    if len(part_bytes) < 0x20 or not ivt_csf_inspect.is_ivt_header(part_bytes, 0):
        return None
    header = struct.unpack_from(">HBB", part_bytes, 0)  # sanity check
    _ = header
    entry, res1, dcd_ptr, bdata_ptr, self_ptr, csf_ptr, res2 = struct.unpack_from(
        "<7I", part_bytes, 4
    )
    # Also inspect raw boot_data relative to XIP 0x60001000 if it falls inside this 4 KiB sector
    raw_bd = None
    bd_rel = bdata_ptr - (NOR_XIP_BASE + part_phys)
    if 0 <= bd_rel and bd_rel + 12 <= len(part_bytes):
        bd_start, bd_len, bd_plugin = struct.unpack_from("<3I", part_bytes, bd_rel)
        raw_bd = {
            "vma": bdata_ptr,
            "file_offset_in_sector": bd_rel,
            "start": bd_start,
            "length": bd_len,
            "end": bd_start + bd_len,
            "plugin": bd_plugin,
        }
    expected_self = NOR_XIP_BASE + part_phys
    if self_ptr == expected_self:
        self_status = "matches 0x60001000 (standard HABv4)"
    elif self_ptr == 0x60001020:
        self_status = "equals 0x60001020 (matches flasher offset note, shifted +0x20 from IVT)"
    else:
        self_status = f"unexpected value 0x{self_ptr:08x}"

    return {
        "tag": part_bytes[0],
        "header_len": struct.unpack_from(">H", part_bytes, 1)[0],
        "version": part_bytes[3],
        "entry": entry,
        "reserved1": res1,
        "dcd_ptr": dcd_ptr,
        "boot_data_ptr": bdata_ptr,
        "self_ptr": self_ptr,
        "csf_ptr": csf_ptr,
        "reserved2": res2,
        "self_matches_ivt_addr": (self_ptr == expected_self),
        "self_status": self_status,
        "boot_data_raw": raw_bd,
    }


def _inspect_code_partition(name, part_phys, part_bytes):
    """Inspect a bootloader or application slot slice (full or partial header sample)."""
    xip_base = NOR_XIP_BASE + part_phys
    out = {}
    if len(part_bytes) >= 0x20:
        sp, reset_vec, nmi, hardfault = struct.unpack_from("<4I", part_bytes, 0)
        trailing_ivt = struct.unpack_from("<I", part_bytes, 0x1C)[0]
        if 0x20000000 <= sp <= 0x20080000 and 0x60000000 <= reset_vec < 0x61000000:
            out["vector_table"] = {
                "initial_sp": sp,
                "reset_handler": reset_vec,
                "trailing_ivt_ptr": trailing_ivt,
            }
    if len(part_bytes) >= 0x500:
        binfo = ivt_csf_inspect.parse_build_info(part_bytes, 0x400)
        if binfo is not None:
            out["build_info"] = binfo
    # Standalone HABv4 or full slot inspection (bootloaders have IVT at +0x000 or +0x400)
    full_info = ivt_csf_inspect.inspect_slot_or_standalone(
        part_bytes, slot_off=0, slot_end=len(part_bytes), label=name
    )
    if full_info is not None:
        out["kind"] = full_info["kind"]
        out["signed_coverage_ok"] = full_info["signed_coverage_ok"]
        if full_info.get("ivt"):
            ivt = full_info["ivt"]
            out["ivt_summary"] = {
                "ivt_offset": ivt["ivt_offset"],
                "entry": ivt["entry"],
                "csf_ptr": ivt["csf_ptr"],
                "self_matches_vma": ivt["self_matches_vma"],
            }
            if ivt.get("csf"):
                csf = ivt["csf"]
                out["csf_summary"] = {
                    "srk_index": csf["srk_index"],
                    "fuse_srk_hash": csf["srk"]["fuse_srk_hash"] if csf.get("srk") else None,
                    "auth_spans": csf["auth_spans"],
                }
        if full_info.get("scatter"):
            out["scatter"] = {
                "itcm_size": full_info["scatter"]["itcm_ramfunc"]["size"],
                "data_size": full_info["scatter"]["data"]["size"],
                "entry_after_init": full_info["scatter"]["entry_after_init"],
            }
    elif out:
        out["kind"] = "partial_slot_sample"
        out["note"] = f"partial slice ({len(part_bytes)} B at XIP 0x{xip_base:08x}); trailing IVT/CSF lies past captured range"
    return out or None


def _format_kvs_value_summary(val, key_name, redact):
    if redact and _is_sensitive_key(key_name):
        if len(val) == 0:
            return {"value_redacted": False, "value_len": 0, "value_display": "(empty)"}
        return {
            "value_redacted": True,
            "value_len": len(val),
            "value_display": f"[REDACTED len={len(val)}]",
        }
    summary = {"value_redacted": False, "value_len": len(val), "value_hex": val.hex()}
    if len(val) >= 4:
        summary["value_u32"] = struct.unpack_from("<I", val, 0)[0]
    if val and all(0x20 <= b < 0x7F for b in val):
        summary["value_ascii"] = val.decode("ascii")
    return summary


def _inspect_kvs_partition(name, part_phys, part_bytes, redact):
    """Run kvs_parse across a single KVS partition slice (4 KiB sector-aligned)."""
    xip_base = NOR_XIP_BASE + part_phys
    reg = kvs_parse.Region(name, xip_base, part_bytes)
    img = kvs_parse.parse_kvs_image([reg], sector_align=SECTOR_SIZE)
    verd = dict(img.verdicts)

    if redact:
        u = verd.get("SsdpUdn")
        if u and u.get("state") == "PRESENT":
            vlen = len(u["value"])
            verd["SsdpUdn"] = {
                "state": "PRESENT",
                "value": f"[REDACTED len={vlen}]",
                "value_len": u["value_len"],
                "offset": u["offset"],
                "crc_ok": u["crc_ok"],
            }

    winner_list = []
    for key in sorted(img.winners.keys()):
        r = img.winners[key]
        item = {
            "key": key,
            "live": r["live"],
            "flags": r["flags"],
            "offset": r["offset"],
            "sector_seq": r["_sector_seq"],
            "crc_ok": (r["crc_stored"] == r["crc_computed"]),
        }
        item.update(_format_kvs_value_summary(r["value"], key, redact))
        winner_list.append(item)

    return {
        "align_used": img.align,
        "sectors": img.sectors,
        "bee_encrypted": bool(img.bee_sectors and not img.sectors),
        "bee_sectors": [asdict(bs) for bs in img.bee_sectors],
        "total_records": len(img.records),
        "crc_valid_records": sum(
            1 for r in img.records if r["crc_stored"] == r["crc_computed"]
        ),
        "winners": winner_list,
        "verdicts": verd,
        "ambiguities": img.ambiguities,
    }


def inspect_nor_slice(data, base_offset=0, redact=True, extract_dir=None, path="<memory>"):
    """Inspect a raw NOR dump slice and return a structured report dict."""
    phys_base = normalize_nor_offset(base_offset)
    phys_end = phys_base + len(data)
    if phys_end > NOR_TOTAL_SIZE:
        raise ValueError(
            f"dump spans 0x{phys_base:06x}..0x{phys_end:06x}, exceeding 16 MiB NOR size (0x{NOR_TOTAL_SIZE:06x})"
        )

    if extract_dir:
        os.makedirs(extract_dir, exist_ok=True)

    regions_out = []
    for name, pid, pstart, psize, kvs_flags, is_sensitive, role in NOR_PARTITIONS:
        pend = pstart + psize
        ov_start = max(phys_base, pstart)
        ov_end = min(phys_end, pend)
        if ov_start >= ov_end:
            continue

        rel_start = ov_start - phys_base
        rel_end = ov_end - phys_base
        part_bytes = data[rel_start:rel_end]
        stats = _sector_stats(part_bytes)
        is_complete = (ov_start == pstart) and (ov_end == pend)
        in_bee_region_1 = (
            kvs_parse.BEE_REGION1_PHYS_START <= pstart
            and pend <= kvs_parse.BEE_REGION1_PHYS_END
        )

        sha256_val = hashlib.sha256(part_bytes).hexdigest()
        if redact and is_sensitive and not stats["erased_only"]:
            sha256_display = "[REDACTED]"
        else:
            sha256_display = sha256_val

        extracted_path = None
        if extract_dir:
            suffix = "" if is_complete else f"_0x{ov_start:06x}"
            fname = f"{name}{suffix}.bin"
            fpath = os.path.join(extract_dir, fname)
            with open(fpath, "wb") as fh:
                fh.write(part_bytes)
            extracted_path = fpath

        entry = {
            "name": name,
            "partition_id": pid,
            "xip_start": NOR_XIP_BASE + ov_start,
            "xip_end": NOR_XIP_BASE + ov_end,
            "phys_start": ov_start,
            "phys_end": ov_end,
            "partition_size": psize,
            "captured_size": len(part_bytes),
            "complete": is_complete,
            "bee_region_1": in_bee_region_1,
            "kvs_flags": {"is_kvs": bool(kvs_flags[0]), "persistent": bool(kvs_flags[1])},
            "role": role,
            "sha256": sha256_display,
            "stats": stats,
        }
        if extracted_path:
            entry["extracted_file"] = extracted_path

        if name == "fcb" and ov_start == 0:
            fcb = parse_fcb(part_bytes, 0)
            if fcb:
                entry["fcb"] = fcb
        elif name == "boot_ivt" and ov_start == pstart:
            boot_ivt = _inspect_boot_ivt(part_bytes, ov_start)
            if boot_ivt:
                entry["boot_ivt"] = boot_ivt
        elif kvs_flags[0] == 1 and not stats["erased_only"]:
            entry["kvs"] = _inspect_kvs_partition(name, ov_start, part_bytes, redact=redact)
        elif name in ("app_slot_a", "bootloader_a", "bootloader_b", "app_slot_b") and not stats["erased_only"] and ov_start == pstart:
            code_info = _inspect_code_partition(name, ov_start, part_bytes)
            if code_info:
                entry["image"] = code_info

        regions_out.append(entry)

    return {
        "path": path,
        "phys_start": phys_base,
        "phys_end": phys_end,
        "xip_start": NOR_XIP_BASE + phys_base,
        "xip_end": NOR_XIP_BASE + phys_end,
        "size": len(data),
        "redact": redact,
        "partitions_found": len(regions_out),
        "partitions": regions_out,
    }


def render_text(report):
    lines = []
    lines.append(
        f"NOR slice: {report['path']}  size={report['size']} B "
        f"(phys 0x{report['phys_start']:06x}..0x{report['phys_end']:06x}, "
        f"XIP 0x{report['xip_start']:08x}..0x{report['xip_end']:08x}, redact={report['redact']})"
    )
    lines.append(f"Partitions covered: {report['partitions_found']}")
    lines.append("")
    for p in report["partitions"]:
        pid_str = f"id={p['partition_id']}" if p["partition_id"] is not None else "raw"
        cov = "full" if p["complete"] else f"partial ({p['captured_size']}/{p['partition_size']} B)"
        st = p["stats"]
        if st["erased_only"]:
            state = "ERASED (0xFF)"
        else:
            state = f"active_4k={st['active_4k']}/{st['chunks_4k']} non_ff={st['non_ff_bytes']} B"
            if p.get("bee_region_1"):
                state += f" blocks_16b={st['populated_16b_blocks']}"
        bee_tag = " [BEE-ECB]" if p.get("bee_region_1") else ""
        lines.append(
            f"- {p['name']} [{pid_str}]{bee_tag} 0x{p['phys_start']:06x}..0x{p['phys_end']:06x} "
            f"(XIP 0x{p['xip_start']:08x}) [{cov}] :: {state}"
        )
        lines.append(f"    sha256: {p['sha256']}")
        if "extracted_file" in p:
            lines.append(f"    extracted: {p['extracted_file']}")
        if "fcb" in p:
            f = p["fcb"]
            lines.append(
                f"    FCB: magic={f['magic']} ver=0x{f['version']:08x} "
                f"a1_size=0x{f['sflash_a1_size']:x} page={f['page_size']} sector={f['sector_size']} "
                f"lut_words={f['nonzero_lut_words']}"
            )
        if "boot_ivt" in p:
            bi = p["boot_ivt"]
            lines.append(
                f"    Boot IVT: ver=0x{bi['version']:02x} entry=0x{bi['entry']:08x} "
                f"self=0x{bi['self_ptr']:08x} ({bi['self_status']}) csf=0x{bi['csf_ptr']:08x}"
            )
            if bi.get("boot_data_raw"):
                bd = bi["boot_data_raw"]
                lines.append(
                    f"    boot_data @+0x{bd['file_offset_in_sector']:x}: start=0x{bd['start']:08x} "
                    f"length=0x{bd['length']:08x} plugin={bd['plugin']}"
                )
        if "kvs" in p:
            k = p["kvs"]
            if k.get("bee_sectors"):
                lines.append(
                    f"    KVS [BEE-ECB]: align={k['align_used']} "
                    f"bee_sectors={len(k['bee_sectors'])} plaintext_sectors={len(k['sectors'])} "
                    f"(AES-128-ECB hardware bus encryption)"
                )
                for bs in k["bee_sectors"]:
                    lines.append(
                        f"      bee-sec[{bs['sector_index']}] @0x{bs['offset']:08x}: "
                        f"state={bs['state']} blocks_16b={bs['encrypted_blocks_16b']} "
                        f"record_blocks_16b={bs['record_blocks_16b']} erased_tail={bs['erased_tail_bytes']} B"
                    )
            else:
                lines.append(
                    f"    KVS: align={k['align_used']} sectors={len(k['sectors'])} "
                    f"records={k['total_records']} crc_ok={k['crc_valid_records']}/{k['total_records']} "
                    f"winners={len(k['winners'])}"
                )
            for w in k["winners"]:
                status = "LIVE" if w["live"] else "DEAD"
                crc_s = "OK" if w["crc_ok"] else "CRC_BAD"
                if "value_display" in w:
                    val_str = w["value_display"]
                elif "value_ascii" in w:
                    val_str = f"{w['value_ascii']!r} (hex={w['value_hex']})"
                elif "value_u32" in w:
                    val_str = f"u32={w['value_u32']} (hex={w['value_hex']})"
                else:
                    val_str = f"hex={w.get('value_hex', '')}"
                lines.append(
                    f"      key={w['key']!r} [{status}, {crc_s}, seq={w['sector_seq']}] -> {val_str}"
                )
            for vk in kvs_parse.KEYS_OF_INTEREST:
                vv = k["verdicts"].get(vk)
                if vv and vv.get("state") != "ABSENT":
                    lines.append(f"      verdict {vk}: {json.dumps(vv, sort_keys=True)}")
        if "image" in p:
            im = p["image"]
            lines.append(f"    Image: kind={im.get('kind')}")
            if im.get("vector_table"):
                vt = im["vector_table"]
                lines.append(
                    f"      vectors: sp=0x{vt['initial_sp']:08x} reset=0x{vt['reset_handler']:08x} "
                    f"trailing_ivt=0x{vt['trailing_ivt_ptr']:08x}"
                )
            if im.get("build_info"):
                b = im["build_info"]
                lines.append(
                    f"      BuildInfo: family={b['family']} build={b['build_number']} type={b['image_type']} flash=0x{b['flash_capacity']:x}"
                )
            if im.get("note"):
                lines.append(f"      note: {im['note']}")
    return "\n".join(lines)


def _build_synthetic_fcb():
    buf = bytearray(0x200)
    buf[0:4] = b"FCFB"
    struct.pack_into("<I", buf, 0x04, 0x56010000)
    buf[0x44] = 1
    buf[0x45] = 4
    struct.pack_into("<I", buf, 0x50, NOR_TOTAL_SIZE)
    struct.pack_into("<I", buf, 0x80, 0x081804EB)
    struct.pack_into("<I", buf, 0x1C0, 256)
    struct.pack_into("<I", buf, 0x1C4, SECTOR_SIZE)
    return bytes(buf)


def _build_synthetic_boot_ivt(self_ptr=0x60001020):
    buf = bytearray(0x40)
    # HABv4 IVT header: tag=0xD1, len=0x0020 (BE), ver=0x41
    buf[0] = ivt_csf_inspect.HAB_TAG_IVT
    struct.pack_into(">H", buf, 1, 0x0020)
    buf[3] = 0x41
    struct.pack_into(
        "<7I",
        buf,
        4,
        0x60800010,  # entry
        0x00000000,  # reserved1
        0x00000000,  # dcd
        0x60001020,  # boot_data
        self_ptr,    # self
        0x60818000,  # csf
        0x00000000,  # reserved2
    )
    struct.pack_into("<3I", buf, 0x20, NOR_XIP_BASE, NOR_TOTAL_SIZE, 0)
    return bytes(buf)


def selftest():
    fails = []

    def check(name, cond):
        print(f"  [{'ok' if cond else 'FAIL'}] {name}")
        if not cond:
            fails.append(name)

    g = 4
    u32v = lambda n: struct.pack("<I", n)

    # Synthetic 256 KiB low NOR slice (0x000000..0x03ffff)
    low = bytearray(b"\xff" * 0x40000)
    fcb = _build_synthetic_fcb()
    low[0x000000 : 0x000000 + len(fcb)] = fcb
    bivt = _build_synthetic_boot_ivt(self_ptr=0x60001020)
    low[0x001000 : 0x001000 + len(bivt)] = bivt
    low[0x006000 : 0x006010] = b"TOMBSTONE-HEADER"

    # id=9 User KVS @ 0x028000
    sec_user = kvs_parse.build_sector(
        10,
        4,
        [kvs_parse.build_record(b"UpdateGauge", u32v(1), live=True, g=g)],
        SECTOR_SIZE,
        g,
    )
    low[0x028000 : 0x028000 + SECTOR_SIZE] = sec_user

    # id=5 Factory KVS @ 0x038000
    sec_fac = kvs_parse.build_sector(
        3,
        4,
        [
            kvs_parse.build_record(b"IsDfDevice", u32v(0), live=True, g=g),
            kvs_parse.build_record(b"SsdpUdn", b"uuid:test-secret-1234", live=True, g=g),
            kvs_parse.build_record(b"BruceMfgDate", b"2020-02-01", live=True, g=g),
        ],
        SECTOR_SIZE,
        g,
    )
    low[0x038000 : 0x038000 + SECTOR_SIZE] = sec_fac

    # id=4 Bootloader KVS @ 0x03c000
    sec_bl = kvs_parse.build_sector(
        5,
        4,
        [
            kvs_parse.build_record(b"BookkeepVer", u32v(8), live=True, g=g),
            kvs_parse.build_record(b"BookkeepMeta", b"\x01\x00", live=True, g=g),
        ],
        SECTOR_SIZE,
        g,
    )
    low[0x03C000 : 0x03C000 + SECTOR_SIZE] = sec_bl

    low_bytes = bytes(low)
    rep_redacted = inspect_nor_slice(low_bytes, base_offset=0x60000000, redact=True, path="selftest_low")
    print(f"selftest: partitions covered = {rep_redacted['partitions_found']}")

    by_name = {p["name"]: p for p in rep_redacted["partitions"]}
    check("low 256 KiB covers all 10 partitions (fcb + 9 partitions)", rep_redacted["partitions_found"] == 10)
    check("FCB parsed correctly", by_name["fcb"].get("fcb", {}).get("sector_size") == SECTOR_SIZE)
    check(
        "Boot IVT parsed and 0x60001020 flagged",
        by_name["boot_ivt"].get("boot_ivt", {}).get("self_ptr") == 0x60001020
        and by_name["boot_ivt"]["boot_ivt"].get("boot_data_raw", {}).get("length") == NOR_TOTAL_SIZE,
    )
    check("id=8 bug_reports non-erased and sha256 redacted", by_name["bug_reports"]["sha256"] == "[REDACTED]")
    check("id=11 bt_nvram erased sha256 still shown", not by_name["bt_nvram"]["stats"]["non_ff_bytes"] and by_name["bt_nvram"]["sha256"] != "[REDACTED]")
    check(
        "id=9 user_kvs UpdateGauge parsed",
        by_name["user_kvs"]["kvs"]["verdicts"]["UpdateGauge"].get("value_u32") == 1,
    )
    fac_winners = {w["key"]: w for w in by_name["factory_kvs"]["kvs"]["winners"]}
    check(
        "id=5 factory_kvs redacts SsdpUdn but keeps BruceMfgDate",
        fac_winners["SsdpUdn"]["value_redacted"] is True
        and "[REDACTED" in fac_winners["SsdpUdn"]["value_display"]
        and "test-secret-1234" not in json.dumps(rep_redacted)
        and fac_winners["BruceMfgDate"]["value_ascii"] == "2020-02-01",
    )
    bl_winners = {w["key"]: w for w in by_name["bootloader_kvs"]["kvs"]["winners"]}
    check(
        "id=4 bootloader_kvs BookkeepVer parsed",
        bl_winners["BookkeepVer"]["value_u32"] == 8 and by_name["bootloader_kvs"]["sha256"] != "[REDACTED]",
    )

    rep_raw = inspect_nor_slice(low_bytes, base_offset=0, redact=False, path="selftest_low")
    raw_fac = {p["name"]: p for p in rep_raw["partitions"]}["factory_kvs"]["kvs"]["winners"]
    raw_ssdp = {w["key"]: w for w in raw_fac}["SsdpUdn"]
    check(
        "--no-redact reveals SsdpUdn",
        raw_ssdp["value_redacted"] is False and raw_ssdp["value_ascii"] == "uuid:test-secret-1234",
    )

    # Partial Slot B BuildInfo sample at 0x60840000 (4 KiB)
    slot_sample = bytearray(b"\xff" * 0x1000)
    struct.pack_into("<2I", slot_sample, 0, 0x2003F688, 0x60840501)
    struct.pack_into("<I", slot_sample, 0x1C, 0x60C37000)
    struct.pack_into("<6I", slot_sample, 0x400, 0x747315A2, 1, 0x100, 2, 0x01000000, 316382)
    struct.pack_into("<I", slot_sample, 0x4FC, 0x4786CD88)
    rep_slot = inspect_nor_slice(bytes(slot_sample), base_offset=0x60840000, path="selftest_slotb")
    slot_b = rep_slot["partitions"][0]
    check(
        "partial Slot B sample decodes BuildInfo 316382",
        slot_b["name"] == "app_slot_b"
        and not slot_b["complete"]
        and slot_b["image"]["build_info"]["build_number"] == 316382,
    )

    # BEE Region 1 flags + synthetic AES-128-ECB encrypted Bootloader KVS check
    check(
        "BEE Region 1 window flagged strictly on 0x006000..0x03ffff partitions",
        by_name["bootloader_kvs"]["bee_region_1"] is True
        and by_name["bug_reports"]["bee_region_1"] is True
        and by_name["bug_reports"]["stats"]["populated_16b_blocks"] == 1
        and by_name["fcb"]["bee_region_1"] is False
        and by_name["boot_ivt"]["bee_region_1"] is False,
    )
    bee_bl = (
        kvs_parse._build_synthetic_bee_sector("standby_formatted", rec_blocks=0, seed_prefix=b"b0")
        + kvs_parse._build_synthetic_bee_sector("active_sequenced", rec_blocks=4, seed_prefix=b"b1")
        + kvs_parse._build_synthetic_bee_sector("active_no_seq", rec_blocks=2, seed_prefix=b"b2")
        + (b"\xff" * 0x1000)
    )
    rep_bee = inspect_nor_slice(bee_bl, base_offset=0x6003C000, path="selftest_bee_bl")
    bee_txt = render_text(rep_bee)
    bee_p = rep_bee["partitions"][0]
    check(
        "BEE-encrypted Bootloader KVS reports bee_encrypted=True and 16B blocks",
        bee_p["name"] == "bootloader_kvs"
        and bee_p["bee_region_1"] is True
        and bee_p["stats"]["populated_16b_blocks"] == 10
        and bee_p["kvs"]["bee_encrypted"] is True
        and bee_p["kvs"]["align_used"] == 16
        and [s["state"] for s in bee_p["kvs"]["bee_sectors"]]
        == ["standby_formatted", "active_sequenced", "active_no_seq"]
        and "KVS [BEE-ECB]" in bee_txt,
    )

    with tempfile.TemporaryDirectory() as td:
        dump_p = os.path.join(td, "low_256k.bin")
        out_dir = os.path.join(td, "carved")
        json_p = os.path.join(td, "report.json")
        with open(dump_p, "wb") as fh:
            fh.write(low_bytes)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main([dump_p, "--extract-dir", out_dir, "--json", json_p])
        check(
            "CLI carved 10 partition files + JSON report",
            rc == 0
            and os.path.isfile(os.path.join(out_dir, "factory_kvs.bin"))
            and os.path.isfile(os.path.join(out_dir, "user_kvs.bin"))
            and os.path.isfile(json_p),
        )

    print("SELFTEST " + ("PASS" if not fails else "FAIL: " + ", ".join(fails)))
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Inspect and carve Stadia Controller NOR flash dumps against the 13-partition map."
    )
    ap.add_argument("dump_file", nargs="?", help="raw NOR dump slice (.bin)")
    ap.add_argument(
        "--base-offset",
        type=lambda s: int(s, 0),
        default=0,
        help="NOR physical offset (0x000000) or XIP address (0x60000000) of byte 0 (default: 0x0)",
    )
    ap.add_argument(
        "--extract-dir",
        metavar="DIR",
        help="write carved per-partition .bin slices into DIR (keep local, do not commit PII)",
    )
    ap.add_argument(
        "--no-redact",
        action="store_true",
        help="include sensitive hashes and KVS values (SsdpUdn/serials/keys) in output",
    )
    ap.add_argument(
        "--json",
        metavar="PATH",
        help="write JSON report to PATH ('-' = stdout, replaces text output)",
    )
    ap.add_argument(
        "--self-test",
        "--selftest",
        dest="self_test",
        action="store_true",
        help="run synthetic self-tests against all 10 low-256 KiB partitions and partial Slot B",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return selftest()
    if not args.dump_file:
        ap.error("dump_file is required unless --self-test is specified")

    with open(args.dump_file, "rb") as fh:
        data = fh.read()

    report = inspect_nor_slice(
        data,
        base_offset=args.base_offset,
        redact=not args.no_redact,
        extract_dir=args.extract_dir,
        path=args.dump_file,
    )

    if args.json == "-":
        print(json.dumps(report, indent=2))
        return 0
    print(render_text(report))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
        print(f"JSON written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
