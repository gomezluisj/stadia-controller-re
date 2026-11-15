#!/usr/bin/env python3
"""ivt_csf_inspect.py - Static HABv4 IVT/CSF, BuildInfo, scatter-load, and
co-processor firmware coverage inspector for Stadia Controller images.

Supports:
  - Standalone HABv4 IVT+CSF binaries (e.g. restricted_ivt_flashloader.bin)
  - Application slot images (bruce / gotham OTA images) with trailing IVT via
    vector table word 7 (*(slot_base + 0x1c)) and BuildInfo block at +0x400
  - Full 16 MiB NOR flash dumps (Boot IVT @ 0x1000, Slot A @ 0x40000,
    Bootloader A/B @ 0x800000/0x820000, Slot B @ 0x840000)

All verification is read-only and offline. Uses Python standard library only.
"""

import argparse
import hashlib
import json
import struct
import sys

BUILD_INFO_MAGIC = 0x747315A2
BUILD_INFO_FOOTER = 0x4786CD88
BRUCE_BUILD_THRESHOLD = 320480  # <= 320480 is gotham, > 320480 is bruce

HAB_TAG_IVT = 0xD1
HAB_TAG_CSF = 0xD4
HAB_TAG_SRK_TBL = 0xD7
HAB_TAG_SRK_KEY = 0xE1

HAB_CMD_SET = 0xB1
HAB_CMD_UNLK = 0xB2
HAB_CMD_INS_KEY = 0xBE
HAB_CMD_NOP = 0xC0
HAB_CMD_AUT_DAT = 0xCA
HAB_CMD_WRT_DAT = 0xCC
HAB_CMD_CHK_DAT = 0xCF

PARTITIONS = (
    ("Boot IVT / FCB", 0x60000000, 0x00040000, 0),
    ("Application A", 0x60040000, 0x007C0000, 1),
    ("Bootloader A", 0x60800000, 0x00020000, 3),
    ("Bootloader B", 0x60820000, 0x00020000, 4),
    ("Application B", 0x60840000, 0x007C0000, 2),
)

SCATTER_NAMES = (
    "data_lma",
    "data_vma_start",
    "data_vma_end",
    "data2_vma_start",
    "data2_vma_end",
    "bss_low_end",
    "itcm_lma",
    "itcm_vma_start",
    "itcm_vma_end",
    "bss_high_start",
    "bss_high_end",
    "stack_start",
    "stack_end",
    "stack_fill",
    "entry_after_init",
)


def u16_be(buf, off):
    return struct.unpack_from(">H", buf, off)[0]


def u32_be(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


def u32_le(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _in_ranges(start, end, ranges):
    """Return True if [start, end) is completely covered by at least one signed span."""
    if start >= end:
        return False
    for r_start, r_end in ranges:
        if r_start <= start and end <= r_end:
            return True
    return False


def classify_partition(vma):
    """Map an XIP reset handler / VMA to Google's flasher partition table."""
    for name, start, size, pid in PARTITIONS:
        if start <= vma < start + size:
            return {"name": name, "base": start, "size": size, "id": pid}
    return None


def is_ivt_header(buf, off):
    """Return True if buf[off:off+32] starts with a valid HABv4 IVT header."""
    if off < 0 or off + 0x20 > len(buf):
        return False
    tag = buf[off]
    hlen = u16_be(buf, off + 1)
    ver = buf[off + 3]
    return tag == HAB_TAG_IVT and hlen == 0x0020 and 0x40 <= ver <= 0x4F


def parse_build_info(buf, off=0x400):
    """Parse the 256-byte BuildInfo header at slot_offset + 0x400."""
    if off < 0 or off + 0x100 > len(buf):
        return None
    hdr, ver, sz, img_type, flash_cap, build_num = struct.unpack_from("<6I", buf, off)
    ftr = u32_le(buf, off + 0xFC)
    if hdr != BUILD_INFO_MAGIC or ftr != BUILD_INFO_FOOTER:
        return None
    family = "gotham" if build_num <= BRUCE_BUILD_THRESHOLD else "bruce"
    return {
        "offset": off,
        "header_magic": hdr,
        "footer_magic": ftr,
        "version": ver,
        "size": sz,
        "image_type": img_type,
        "flash_capacity": flash_cap,
        "build_number": build_num,
        "family": family,
    }


def parse_srk_table(buf, srk_off):
    """Parse a HABv4 SRK table (tag 0xD7) and derive its OCOTP fuse hash."""
    if srk_off < 0 or srk_off + 4 > len(buf) or buf[srk_off] != HAB_TAG_SRK_TBL:
        return None
    tbl_len = u16_be(buf, srk_off + 1)
    if tbl_len < 4 or srk_off + tbl_len > len(buf):
        return None
    tbl_bytes = buf[srk_off : srk_off + tbl_len]
    keys = []
    pos = 4
    key_digests = bytearray()
    while pos + 12 <= tbl_len:
        ktag = tbl_bytes[pos]
        klen = u16_be(tbl_bytes, pos + 1)
        if ktag != HAB_TAG_SRK_KEY or klen < 12 or pos + klen > tbl_len:
            break
        alg = tbl_bytes[pos + 4]
        mod_bytes = u16_be(tbl_bytes, pos + 8)
        exp_bytes = u16_be(tbl_bytes, pos + 10)
        key_blob = tbl_bytes[pos : pos + klen]
        key_digests.extend(hashlib.sha256(key_blob).digest())
        keys.append(
            {
                "index": len(keys),
                "length": klen,
                "alg": alg,
                "rsa_bits": mod_bytes * 8,
                "exp_bytes": exp_bytes,
                "sha256": hashlib.sha256(key_blob).hexdigest(),
            }
        )
        pos += klen
    return {
        "offset": srk_off,
        "length": tbl_len,
        "version": tbl_bytes[3],
        "table_sha256": hashlib.sha256(tbl_bytes).hexdigest(),
        "fuse_srk_hash": hashlib.sha256(bytes(key_digests)).hexdigest(),
        "keys": keys,
    }


def parse_csf(buf, csf_off):
    """Parse a HABv4 CSF (tag 0xD4) and extract keys, writes, and AUTHENTICATE_DATA spans."""
    if csf_off < 0 or csf_off + 4 > len(buf) or buf[csf_off] != HAB_TAG_CSF:
        return None
    hdr_len = u16_be(buf, csf_off + 1)
    ver = buf[csf_off + 3]
    if hdr_len < 4 or csf_off + hdr_len > len(buf):
        return None
    commands = []
    auth_spans = []
    srk_info = None
    src_key_idx = None
    pos = csf_off + 4
    end = csf_off + hdr_len
    while pos + 4 <= end:
        tag = buf[pos]
        clen = u16_be(buf, pos + 1)
        param = buf[pos + 3]
        if clen < 4 or pos + clen > end:
            break
        cmd_bytes = buf[pos : pos + clen]
        entry = {"tag": tag, "length": clen, "param": param}
        if tag == HAB_CMD_INS_KEY and clen >= 12:
            proto = cmd_bytes[4]
            alg = cmd_bytes[5]
            sidx = cmd_bytes[6]
            tidx = cmd_bytes[7]
            kdat = u32_be(cmd_bytes, 8)
            entry.update(
                {
                    "name": "INSTALL_SRK" if proto == 0x03 else ("INSTALL_CSFK" if param & 0x02 else "INSTALL_KEY"),
                    "protocol": proto,
                    "alg": alg,
                    "src_index": sidx,
                    "target_index": tidx,
                    "key_data_rel": kdat,
                }
            )
            if proto == 0x03:
                src_key_idx = sidx
                srk_info = parse_srk_table(buf, csf_off + kdat)
        elif tag == HAB_CMD_AUT_DAT and clen >= 12:
            key_slot = cmd_bytes[4]
            pcl = cmd_bytes[5]
            eng = cmd_bytes[6]
            sig_rel = u32_be(cmd_bytes, 8)
            blocks = []
            bpos = 12
            while bpos + 8 <= clen:
                rstart = u32_be(cmd_bytes, bpos)
                rlen = u32_be(cmd_bytes, bpos + 4)
                blocks.append({"start": rstart, "length": rlen, "end": rstart + rlen})
                auth_spans.append((rstart, rstart + rlen))
                bpos += 8
            entry.update(
                {
                    "name": "AUTHENTICATE_DATA" if blocks else "AUTHENTICATE_CSF",
                    "key_slot": key_slot,
                    "protocol": pcl,
                    "engine": eng,
                    "sig_rel": sig_rel,
                    "blocks": blocks,
                }
            )
        elif tag == HAB_CMD_WRT_DAT and clen >= 12:
            writes = []
            wpos = 4
            while wpos + 8 <= clen:
                writes.append({"addr": u32_be(cmd_bytes, wpos), "value": u32_be(cmd_bytes, wpos + 4)})
                wpos += 8
            entry.update({"name": "WRITE_DATA", "writes": writes})
        elif tag == HAB_CMD_UNLK and clen >= 8:
            entry.update({"name": "UNLOCK", "engine": param, "features": u32_be(cmd_bytes, 4)})
        elif tag == HAB_CMD_CHK_DAT and clen >= 16:
            entry.update({"name": "CHECK_DATA", "addr": u32_be(cmd_bytes, 8), "mask": u32_be(cmd_bytes, 12)})
        elif tag == HAB_CMD_SET:
            entry["name"] = "SET"
        elif tag == HAB_CMD_NOP:
            entry["name"] = "NOP"
        else:
            entry["name"] = f"CMD_0x{tag:02X}"
        commands.append(entry)
        pos += clen
    return {
        "offset": csf_off,
        "header_len": hdr_len,
        "version": ver,
        "srk_index": src_key_idx,
        "srk": srk_info,
        "commands": commands,
        "auth_spans": auth_spans,
    }


def parse_scatter_table(buf, slot_off=0):
    """Parse Reset_Handler literal pool at slot_off + 0x5f4..0x630."""
    pool_off = slot_off + 0x5F4
    if pool_off < 0 or pool_off + 60 > len(buf):
        return None
    words = struct.unpack_from("<15I", buf, pool_off)
    raw = dict(zip(SCATTER_NAMES, words))
    # Sanity checks matching Reset_Handler layout in bruce and gotham
    if (
        raw["data2_vma_start"] != 0x20000000
        or raw["itcm_vma_start"] != 0x00000000
        or raw["stack_fill"] != 0xAABBAABB
        or not (raw["data_vma_start"] < raw["data_vma_end"] <= raw["bss_high_start"])
        or not (raw["bss_high_start"] < raw["bss_high_end"] <= raw["stack_start"] < raw["stack_end"])
    ):
        return None
    data_size = raw["data_vma_end"] - raw["data_vma_start"]
    return {
        "pool_offset": pool_off,
        "bss_low": {"start": 0x20000000, "end": raw["bss_low_end"], "size": raw["bss_low_end"] - 0x20000000},
        "data": {
            "lma": raw["data_lma"],
            "vma_start": raw["data_vma_start"],
            "vma_end": raw["data_vma_end"],
            "size": data_size,
        },
        "noinit": {
            "start": raw["data_vma_end"],
            "end": raw["bss_high_start"],
            "size": raw["bss_high_start"] - raw["data_vma_end"],
        },
        "bss_high": {
            "start": raw["bss_high_start"],
            "end": raw["bss_high_end"],
            "size": raw["bss_high_end"] - raw["bss_high_start"],
        },
        "stack": {
            "start": raw["stack_start"],
            "end": raw["stack_end"],
            "size": raw["stack_end"] - raw["stack_start"],
            "fill": raw["stack_fill"],
        },
        "itcm_ramfunc": {
            "lma": raw["itcm_lma"],
            "vma_start": raw["itcm_vma_start"],
            "vma_end": raw["itcm_vma_end"],
            "size": raw["itcm_vma_end"] - raw["itcm_vma_start"],
        },
        "entry_after_init": raw["entry_after_init"],
    }


def find_coproc_blobs(buf, slot_off, slot_end, base_vma, auth_spans):
    """Locate embedded BCM43458F .hcd patchram and WLAN firmware markers inside [slot_off, slot_end)."""
    region = buf[slot_off:slot_end]
    result = {"bt_hcd": None, "wlan_markers": []}

    ver_idx = region.find(b";BCM43458F")
    if ver_idx != -1:
        endz = region.find(b"\x00", ver_idx)
        ver_str = region[ver_idx : (endz if endz != -1 else ver_idx + 80)].decode("ascii", "replace")
        scan_lo = max(0, ver_idx - 0x200)
        hcd_start = None
        hcd_end = None
        hcd_records = 0
        for probe in range(scan_lo, ver_idx + 1):
            pos = probe
            cnt = 0
            while pos + 3 <= len(region):
                op = struct.unpack_from("<H", region, pos)[0]
                rlen = region[pos + 2]
                if pos + 3 + rlen > len(region):
                    break
                if op == 0xFC4C:
                    cnt += 1
                    pos += 3 + rlen
                elif op == 0xFC4E and cnt >= 4:
                    cnt += 1
                    pos += 3 + rlen
                    hcd_start = slot_off + probe
                    hcd_end = slot_off + pos
                    hcd_records = cnt
                    break
                else:
                    break
            if hcd_start is not None:
                break
        if hcd_start is None:
            # Fallback if synthetic image has fewer records or marker without full stream
            vma_s = base_vma + (slot_off + ver_idx - slot_off)
            vma_e = vma_s + len(ver_str)
            result["bt_hcd"] = {
                "version": ver_str,
                "file_start": slot_off + ver_idx,
                "file_end": slot_off + ver_idx + len(ver_str),
                "size": len(ver_str),
                "records": 0,
                "vma_start": vma_s,
                "vma_end": vma_e,
                "inside_signed_span": _in_ranges(vma_s, vma_e, auth_spans),
            }
        else:
            vma_s = base_vma + (hcd_start - slot_off)
            vma_e = base_vma + (hcd_end - slot_off)
            result["bt_hcd"] = {
                "version": ver_str,
                "file_start": hcd_start,
                "file_end": hcd_end,
                "size": hcd_end - hcd_start,
                "records": hcd_records,
                "vma_start": vma_s,
                "vma_end": vma_e,
                "inside_signed_span": _in_ranges(vma_s, vma_e, auth_spans),
            }

    for marker_name, pat in (("nvram", b"macaddr="), ("wlan_fw", b"43458c5-roml/")):
        m_idx = region.find(pat)
        if m_idx != -1:
            endz = region.find(b"\x00", m_idx)
            preview = region[m_idx : (endz if endz != -1 and endz - m_idx <= 96 else m_idx + 64)].decode(
                "ascii", "replace"
            )
            vma_s = base_vma + m_idx
            vma_e = vma_s + len(preview)
            result["wlan_markers"].append(
                {
                    "kind": marker_name,
                    "file_offset": slot_off + m_idx,
                    "vma": vma_s,
                    "preview": preview,
                    "inside_signed_span": _in_ranges(vma_s, vma_e, auth_spans),
                }
            )
    return result


def inspect_ivt_at(buf, ivt_off, slot_off=0, max_end=None):
    """Parse IVT, boot_data, CSF, and compute VMA translation from IVT.self."""
    if max_end is None:
        max_end = len(buf)
    if not is_ivt_header(buf, ivt_off):
        return None
    entry, res1, dcd_ptr, bdata_ptr, self_ptr, csf_ptr, res2 = struct.unpack_from("<7I", buf, ivt_off + 4)
    base_vma = self_ptr - (ivt_off - slot_off)

    boot_data = None
    bd_rel = bdata_ptr - base_vma
    if 0 <= slot_off + bd_rel and slot_off + bd_rel + 12 <= max_end:
        bd_start, bd_len, bd_plugin = struct.unpack_from("<3I", buf, slot_off + bd_rel)
        boot_data = {
            "vma": bdata_ptr,
            "start": bd_start,
            "length": bd_len,
            "end": bd_start + bd_len,
            "plugin": bd_plugin,
        }

    csf = None
    if csf_ptr:
        csf_rel = csf_ptr - base_vma
        csf_file_off = slot_off + csf_rel
        if slot_off <= csf_file_off < max_end:
            csf = parse_csf(buf, csf_file_off)

    return {
        "ivt_offset": ivt_off,
        "version": buf[ivt_off + 3],
        "base_vma": base_vma,
        "entry": entry,
        "reserved1": res1,
        "dcd_ptr": dcd_ptr,
        "boot_data_ptr": bdata_ptr,
        "self_ptr": self_ptr,
        "csf_ptr": csf_ptr,
        "reserved2": res2,
        "self_matches_vma": (self_ptr == base_vma + (ivt_off - slot_off)),
        "boot_data": boot_data,
        "csf": csf,
    }


def inspect_slot_or_standalone(buf, slot_off=0, slot_end=None, label=None):
    """Inspect a single image (application slot or standalone IVT+CSF blob)."""
    if slot_end is None:
        slot_end = len(buf)
    size = slot_end - slot_off

    # Case 1: Standalone HABv4 image (IVT at +0x000 or +0x400)
    for ivt_candidate in (slot_off, slot_off + 0x400):
        if is_ivt_header(buf, ivt_candidate):
            ivt_info = inspect_ivt_at(buf, ivt_candidate, slot_off=slot_off, max_end=slot_end)
            auth_spans = ivt_info["csf"]["auth_spans"] if ivt_info and ivt_info["csf"] else []
            return {
                "label": label or "standalone_ivt",
                "kind": "standalone_ivt",
                "file_offset": slot_off,
                "size": size,
                "ivt": ivt_info,
                "build_info": None,
                "scatter": None,
                "coproc": None,
                "signed_coverage_ok": bool(
                    ivt_info and auth_spans and _in_ranges(ivt_info["base_vma"], ivt_info["csf_ptr"], auth_spans)
                ),
            }

    # Case 2: ARM Cortex-M7 slot image with vector table + trailing IVT at word 7 (+0x1c)
    if size >= 0x500:
        initial_sp, reset_vec = struct.unpack_from("<II", buf, slot_off)
        ivt_vma = u32_le(buf, slot_off + 0x1C)
        part = classify_partition(reset_vec)
        if (
            0x20000000 <= initial_sp <= 0x20080000
            and 0x60000000 <= reset_vec < 0x61000000
            and part is not None
        ):
            base_vma = part["base"]
            ivt_rel = ivt_vma - base_vma
            ivt_info = None
            if 0 <= ivt_rel < size:
                ivt_info = inspect_ivt_at(buf, slot_off + ivt_rel, slot_off=slot_off, max_end=slot_end)
            build_info = parse_build_info(buf, slot_off + 0x400)
            scatter = parse_scatter_table(buf, slot_off)
            auth_spans = ivt_info["csf"]["auth_spans"] if ivt_info and ivt_info["csf"] else []
            coproc = find_coproc_blobs(buf, slot_off, slot_end, base_vma, auth_spans)

            signed_ok = False
            if ivt_info and ivt_info["csf_ptr"] and auth_spans:
                signed_ok = _in_ranges(base_vma, ivt_info["csf_ptr"], auth_spans)
            if build_info and auth_spans:
                bi_vma = base_vma + 0x400
                signed_ok = signed_ok and _in_ranges(bi_vma, bi_vma + 0x100, auth_spans)
            if scatter and auth_spans:
                d_s = scatter["data"]["lma"]
                d_e = d_s + scatter["data"]["size"]
                signed_ok = signed_ok and _in_ranges(d_s, d_e, auth_spans)

            return {
                "label": label or part["name"],
                "kind": "application_slot",
                "file_offset": slot_off,
                "size": size,
                "partition": part,
                "vector_table": {
                    "initial_sp": initial_sp,
                    "reset_handler": reset_vec,
                    "trailing_ivt_ptr": ivt_vma,
                },
                "build_info": build_info,
                "ivt": ivt_info,
                "scatter": scatter,
                "coproc": coproc,
                "signed_coverage_ok": signed_ok,
            }

    return None


def inspect_image(data, path="<memory>"):
    """Inspect a single firmware binary or a full 16 MiB NOR dump."""
    digest = hashlib.sha256(data).hexdigest()

    # Detect full 16 MiB NOR dump by checking Boot IVT @ +0x1000 and FCB header ("FCFB")
    if len(data) >= 0x00850000 and is_ivt_header(data, 0x1000):
        boot_ivt = inspect_ivt_at(data, 0x1000, slot_off=0, max_end=len(data))
        regions = []
        for pname, base, psize, _ in PARTITIONS[1:]:
            off = base - 0x60000000
            end = min(len(data), off + psize)
            if off < len(data):
                res = inspect_slot_or_standalone(data, slot_off=off, slot_end=end, label=pname)
                if res is not None:
                    regions.append(res)
        return {
            "path": path,
            "sha256": digest,
            "total_size": len(data),
            "mode": "full_nor_dump",
            "boot_ivt": boot_ivt,
            "regions": regions,
        }

    single = inspect_slot_or_standalone(data, slot_off=0, slot_end=len(data), label=path)
    if single is None:
        raise ValueError(f"{path}: unrecognized image format (no valid HABv4 IVT or slot vector table)")
    return {
        "path": path,
        "sha256": digest,
        "total_size": len(data),
        "mode": single["kind"],
        "image": single,
    }


def _print_ivt_csf(ivt, indent="  "):
    if not ivt:
        print(f"{indent}IVT: <missing or invalid>")
        return
    print(
        f"{indent}IVT @+0x{ivt['ivt_offset']:x}: ver=0x{ivt['version']:02x} base=0x{ivt['base_vma']:08x} "
        f"entry=0x{ivt['entry']:08x} self=0x{ivt['self_ptr']:08x} csf=0x{ivt['csf_ptr']:08x} dcd=0x{ivt['dcd_ptr']:08x}"
    )
    if ivt["boot_data"]:
        bd = ivt["boot_data"]
        print(f"{indent}boot_data @0x{bd['vma']:08x}: start=0x{bd['start']:08x} len=0x{bd['length']:08x} plugin={bd['plugin']}")
    csf = ivt["csf"]
    if not csf:
        print(f"{indent}CSF: <none>")
        return
    print(f"{indent}CSF @+0x{csf['offset']:x}: ver=0x{csf['version']:02x} cmds_len={csf['header_len']} B srk_idx={csf['srk_index']}")
    if csf["srk"]:
        srk = csf["srk"]
        bits = srk["keys"][0]["rsa_bits"] if srk["keys"] else 0
        print(
            f"{indent}  SRK table ({len(srk['keys'])}x RSA-{bits}): "
            f"table_sha256={srk['table_sha256'][:16]}... fuse_hash={srk['fuse_srk_hash']}"
        )
    for cmd in csf["commands"]:
        cname = cmd["name"]
        if cname == "AUTHENTICATE_DATA":
            spans = ", ".join(f"[0x{b['start']:08x}..0x{b['end']:08x}) (0x{b['length']:x} B)" for b in cmd["blocks"])
            print(f"{indent}  - {cname} (key={cmd['key_slot']}): {spans}")
        elif cname == "WRITE_DATA":
            pairs = ", ".join(f"*(0x{w['addr']:08x})=0x{w['value']:08x}" for w in cmd["writes"])
            print(f"{indent}  - {cname}: {pairs}")
        elif cname == "UNLOCK":
            print(f"{indent}  - {cname}: engine=0x{cmd['engine']:02x} features=0x{cmd['features']:08x}")
        else:
            extra = f" src={cmd.get('src_index')} tgt={cmd.get('target_index')}" if "target_index" in cmd else ""
            print(f"{indent}  - {cname}{extra}")


def _print_slot(img, indent=""):
    if img.get("partition"):
        p = img["partition"]
        vt = img["vector_table"]
        print(
            f"{indent}Slot: {p['name']} (id={p['id']}, base=0x{p['base']:08x}, max=0x{p['size']:x} B) | "
            f"SP=0x{vt['initial_sp']:08x} Reset=0x{vt['reset_handler']:08x}"
        )
    bi = img.get("build_info")
    if bi:
        print(
            f"{indent}BuildInfo @+0x{bi['offset']:x}: build={bi['build_number']} ({bi['family']}) "
            f"ver={bi['version']} flash=0x{bi['flash_capacity']:x}"
        )
    _print_ivt_csf(img.get("ivt"), indent=indent)
    sc = img.get("scatter")
    if sc:
        print(f"{indent}Scatter-load:")
        print(f"{indent}  ITCM .ramfunc : LMA 0x{sc['itcm_ramfunc']['lma']:08x} -> VMA 0x{sc['itcm_ramfunc']['vma_start']:08x}..0x{sc['itcm_ramfunc']['vma_end']:08x} ({sc['itcm_ramfunc']['size']} B)")
        print(f"{indent}  DTCM .bss_low : 0x{sc['bss_low']['start']:08x}..0x{sc['bss_low']['end']:08x} ({sc['bss_low']['size']} B)")
        print(f"{indent}  DTCM .data    : LMA 0x{sc['data']['lma']:08x} -> VMA 0x{sc['data']['vma_start']:08x}..0x{sc['data']['vma_end']:08x} ({sc['data']['size']} B)")
        print(f"{indent}  DTCM .noinit  : 0x{sc['noinit']['start']:08x}..0x{sc['noinit']['end']:08x} ({sc['noinit']['size']} B)")
        print(f"{indent}  DTCM .bss_high: 0x{sc['bss_high']['start']:08x}..0x{sc['bss_high']['end']:08x} ({sc['bss_high']['size']} B)")
        print(f"{indent}  DTCM .stack   : 0x{sc['stack']['start']:08x}..0x{sc['stack']['end']:08x} ({sc['stack']['size']} B, fill=0x{sc['stack']['fill']:08x})")
    cp = img.get("coproc")
    if cp and (cp["bt_hcd"] or cp["wlan_markers"]):
        print(f"{indent}Co-processor blobs:")
        if cp["bt_hcd"]:
            bt = cp["bt_hcd"]
            print(
                f"{indent}  BT .hcd: {bt['version']} @ 0x{bt['vma_start']:08x}..0x{bt['vma_end']:08x} "
                f"({bt['size']} B, {bt['records']} records, in_csf={bt['inside_signed_span']})"
            )
        for wm in cp["wlan_markers"]:
            print(
                f"{indent}  WLAN ({wm['kind']}): @ 0x{wm['vma']:08x} in_csf={wm['inside_signed_span']} {wm['preview']!r}"
            )
    print(f"{indent}Signed span coverage check: {'PASS' if img['signed_coverage_ok'] else 'FAIL'}")


def format_report(report):
    print(f"File: {report['path']} ({report['total_size']} B, sha256={report['sha256']})")
    if report["mode"] == "full_nor_dump":
        print("Mode: Full 16 MiB NOR dump")
        _print_ivt_csf(report["boot_ivt"], indent="  ")
        for reg in report["regions"]:
            print(f"\n--- {reg['label']} (+0x{reg['file_offset']:x}) ---")
            _print_slot(reg, indent="  ")
    else:
        _print_slot(report["image"], indent="  ")


def _build_synthetic_csf(auth_start, auth_len):
    """Build a minimal deterministic HABv4 CSF with 1 SRK + 1 AUTHENTICATE_DATA command."""
    srk_key = bytearray(16)
    srk_key[0] = HAB_TAG_SRK_KEY
    struct.pack_into(">H", srk_key, 1, 16)
    srk_key[3] = 0x21
    struct.pack_into(">HH", srk_key, 8, 512, 3)

    srk_tbl = bytearray(4) + srk_key
    srk_tbl[0] = HAB_TAG_SRK_TBL
    struct.pack_into(">H", srk_tbl, 1, len(srk_tbl))
    srk_tbl[3] = 0x40

    # CSF header (4 B) + INS_KEY SRK (12 B) + AUT_DAT (20 B) = 36 B command stream
    srk_rel = 36
    cmd_srk = struct.pack(">BHBBBBBI", HAB_CMD_INS_KEY, 12, 0x00, 0x03, 0x17, 2, 0, srk_rel)
    cmd_aut = struct.pack(">BHBBBBIII", HAB_CMD_AUT_DAT, 20, 0x00, 2, 0xC5, 0x1B, srk_rel + len(srk_tbl), auth_start, auth_len)
    # Fix AUT_DAT format: B(tag) H(len) B(flags) B(key) B(pcl) B(eng) B(cfg) I(sig) I(start) I(len) = 20 B
    cmd_aut = struct.pack(">BHBBBBBIII", HAB_CMD_AUT_DAT, 20, 0x00, 2, 0xC5, 0x1B, 0x00, srk_rel + len(srk_tbl), auth_start, auth_len)
    hdr_len = 4 + len(cmd_srk) + len(cmd_aut)
    csf_hdr = struct.pack(">BHB", HAB_TAG_CSF, hdr_len, 0x42)
    return csf_hdr + cmd_srk + cmd_aut + bytes(srk_tbl)


def _make_ivt(entry, dcd, bdata, self_ptr, csf_ptr):
    return struct.pack(">BHB", HAB_TAG_IVT, 0x0020, 0x41) + struct.pack(
        "<7I", entry, 0, dcd, bdata, self_ptr, csf_ptr, 0
    )


def run_selftest():
    checks = 0

    # Test 1: Synthetic Application Slot image (Slot A 0x60040000)
    base = 0x60040000
    ivt_off = 0x3000
    csf_off = ivt_off + 0x30
    img = bytearray(b"\xFF" * (csf_off + 0x200))
    struct.pack_into("<2I", img, 0x00, 0x2002B828, base + 0x501)
    struct.pack_into("<I", img, 0x1C, base + ivt_off)

    # BuildInfo @ +0x400
    struct.pack_into("<6I", img, 0x400, BUILD_INFO_MAGIC, 1, 0x100, 2, 0x1000000, 337784)
    struct.pack_into("<I", img, 0x4FC, BUILD_INFO_FOOTER)

    # Scatter literal pool @ +0x5f4
    struct.pack_into(
        "<15I",
        img,
        0x5F4,
        base + 0x2000,  # data_lma
        0x20002740,
        0x20002840,
        0x20000000,
        0x20000000,
        0x20002740,
        base + 0x081C,  # itcm_lma
        0x00000000,
        0x00001000,
        0x20002900,
        0x2002A824,
        0x2002A828,
        0x2002B828,
        0xAABBAABB,
        base + 0x0901,
    )

    # Synthetic 5-record .hcd stream (4x FC4C + 1x FC4E) containing ;BCM43458F
    rec_ver = b"\x00\x00\x00\x00;BCM43458F Synthetic BT4.2\x00"
    hcd_stream = bytearray()
    for _ in range(4):
        hcd_stream += struct.pack("<HB", 0xFC4C, len(rec_ver)) + rec_ver
    hcd_stream += struct.pack("<HB", 0xFC4E, 4) + b"\x00\x00\x00\x00"
    img[0x1000 : 0x1000 + len(hcd_stream)] = hcd_stream

    # IVT + boot_data + CSF at ivt_off
    img[ivt_off : ivt_off + 0x20] = _make_ivt(base, 0, base + ivt_off + 0x20, base + ivt_off, base + csf_off)
    struct.pack_into("<3I", img, ivt_off + 0x20, base, 0x007C0000, 0)
    csf_bytes = _build_synthetic_csf(base, csf_off)
    img[csf_off : csf_off + len(csf_bytes)] = csf_bytes

    r1 = inspect_image(bytes(img), "<synthetic-app>")["image"]
    assert r1["kind"] == "application_slot"; checks += 1
    assert r1["build_info"]["build_number"] == 337784; checks += 1
    assert r1["build_info"]["family"] == "bruce"; checks += 1
    assert r1["partition"]["name"] == "Application A"; checks += 1
    assert r1["scatter"]["data"]["size"] == 0x100; checks += 1
    assert r1["scatter"]["itcm_ramfunc"]["size"] == 0x1000; checks += 1
    assert r1["scatter"]["noinit"]["size"] == 0xC0; checks += 1
    assert r1["ivt"]["csf"]["srk_index"] == 2; checks += 1
    assert r1["coproc"]["bt_hcd"]["records"] == 5; checks += 1
    assert r1["coproc"]["bt_hcd"]["inside_signed_span"] is True; checks += 1
    assert r1["signed_coverage_ok"] is True; checks += 1

    # Test 2: Synthetic standalone IVT+CSF (flashloader layout, IVT at +0x400)
    fl = bytearray(0x2000)
    fl_base = 0x20000000
    fl[0x400:0x420] = _make_ivt(fl_base + 0x1000, 0, fl_base + 0x420, fl_base + 0x400, fl_base + 0x1800)
    struct.pack_into("<3I", fl, 0x420, fl_base, 0x00019000, 0)
    fl_csf = _build_synthetic_csf(fl_base, 0x1800)
    fl[0x1800 : 0x1800 + len(fl_csf)] = fl_csf

    r2 = inspect_image(bytes(fl), "<synthetic-fl>")["image"]
    assert r2["kind"] == "standalone_ivt"; checks += 1
    assert r2["ivt"]["base_vma"] == 0x20000000; checks += 1
    assert r2["ivt"]["boot_data"]["length"] == 0x00019000; checks += 1
    assert r2["signed_coverage_ok"] is True; checks += 1

    # Test 3: Tamper / out-of-coverage detection (HCD placed outside signed span)
    img2 = bytearray(img)
    csf_short = _build_synthetic_csf(base, 0x0F00)  # stops before HCD @ +0x1000
    img2[csf_off : csf_off + len(csf_short)] = csf_short
    r3 = inspect_image(bytes(img2), "<synthetic-short>")["image"]
    assert r3["coproc"]["bt_hcd"]["inside_signed_span"] is False; checks += 1
    assert r3["signed_coverage_ok"] is False; checks += 1

    # Test 4: Gotham threshold check
    img3 = bytearray(img)
    struct.pack_into("<I", img3, 0x414, 282115)
    r4 = inspect_image(bytes(img3), "<synthetic-gotham>")["image"]
    assert r4["build_info"]["family"] == "gotham"; checks += 1

    print(f"SELFTEST OK ({checks} checks)")


def main():
    ap = argparse.ArgumentParser(description="Inspect Stadia HABv4 IVT/CSF, BuildInfo, and scatter-load layout.")
    ap.add_argument("image", nargs="?", help="Path to firmware image or 16 MiB NOR dump")
    ap.add_argument("--json", action="store_true", help="Emit JSON output instead of human-readable report")
    ap.add_argument("--selftest", action="store_true", help="Run offline synthetic self-tests")
    args = ap.parse_args()

    if args.selftest:
        run_selftest()
        return 0
    if not args.image:
        ap.error("Provide an image path or --selftest")

    with open(args.image, "rb") as fh:
        data = fh.read()
    report = inspect_image(data, path=args.image)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        format_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
