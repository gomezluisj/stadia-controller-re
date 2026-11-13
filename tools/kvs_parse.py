#!/usr/bin/env python3
"""kvs_parse.py - parser for the Stadia controller key_value_store (KVS) NOR dumps.

Format (reversed from gotham 235551, verified line-equivalent in bruce 337784;
see kvs-parser-spec.md for code addresses):

  Sector header (16 B):
    +0x00 u16 magic 0xABCD | +0x02 u16 version (2..4) | +0x04..0x07 metadata
    +0x08 u64 sequence (LE) -- generation counter, higher = newer sector
    records start at sector + 16

  Record header (8 B):
    +0x00 u16 magic 0x55AA | +0x02 u16 CRC-16/CCITT-FALSE over key||value
    +0x04 u16 flags (bit 0 = record NOT live / tombstone)
    +0x06 u16 (value_len << 4) | key_len
    key   at record + align(8)
    value at record + align(8) + align(key_len)
    total = align(8) + align(key_len) + align(value_len)
    align() rounds up to the store granularity (runtime byte, statically
    unknown; the parser auto-detects it among {4,1,2,8} scored by CRC hits)

  Winner resolution (mount semantics, FUN_6020415E): per key, the record in
  the sector with the highest sequence wins; ties within a sector go to the
  highest offset. If the winning record is a tombstone (flags bit 0 = 1) the
  key reads as ABSENT in the firmware.

Usage:
  python3 kvs_parse.py --region gap1.bin@0x60002000 \
                       --region gap2.bin@0x60424000 \
                       --region tail.bin@0x60C24000 --json result.json
  python3 kvs_parse.py --selftest
Stdlib only. Default CLI --sector-align is 0x1000 (4 KB NOR erase sectors;
pass --sector-align 0 for unaligned synthetic blobs).
"""

import argparse
import contextlib
import io
import json
import os
import struct
import sys
import tempfile

SECTOR_MAGIC = 0xABCD
RECORD_MAGIC = 0x55AA
SECTOR_VERSIONS = (2, 3, 4)
ALIGN_CANDIDATES = (4, 1, 2, 8)
KEYS_OF_INTEREST = ("IsDfDevice", "SsdpUdn", "UpdateGauge")

# ---------------------------------------------------------------- CRC ------
# CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, refin/out False, xorout 0.
# Proven by: update routine FUN_60204DAC + wrapper FUN_602E2E5C in gotham
# (table at VA 0x60328C34; generated table matches the in-image table byte
# for byte in both gotham and bruce), check("123456789") == 0x29B1.

def _gen_crc_table():
    tbl = []
    for i in range(256):
        c = i << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        tbl.append(c)
    return tbl

_CRC_TABLE = _gen_crc_table()

def crc16(data, crc=0xFFFF):
    for b in data:
        crc = _CRC_TABLE[((crc >> 8) ^ b) & 0xFF] ^ ((crc << 8) & 0xFFFF)
    return crc

def record_crc(key_bytes, value_bytes):
    """CRC as the firmware computes it (GetValue, FUN_60203EA0):
    chained update over the key bytes, then over the value bytes."""
    return crc16(value_bytes, crc16(key_bytes))

# ------------------------------------------------------------- helpers -----

def align_up(g, x):
    """FUN_602E2D6C: round x up to a multiple of g (0 stays 0)."""
    r = x % g
    return x if r == 0 else x + g - r

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]

def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]

class Region:
    def __init__(self, name, base, data):
        self.name = name
        self.base = base
        self.data = data

# ---------------------------------------------------------- sector scan ----

def find_sector_candidates(region, sector_align=None):
    """Offsets (region-relative) of plausible sector headers: magic +
    version in range, and the record area either starts with a record magic
    or is uniformly erased/zero (formatted-but-empty / padded sector).

    If sector_align is given (default 0x1000 when parsing real NOR regions,
    off for synthetic buffers), only offsets aligned to it are accepted —
    a 0xABCD appearing inside record payload data can never be mistaken
    for a sector header, because records do not start on sector boundaries."""
    data = region.data
    out = []
    start = 0
    while True:
        i = data.find(b"\xcd\xab", start)
        if i < 0:
            break
        start = i + 1
        if sector_align and (i % sector_align) != 0:
            continue
        if i + 16 > len(data):
            continue
        ver = u16(data, i + 2)
        if ver not in SECTOR_VERSIONS:
            continue
        probe = data[i + 16:i + 16 + 64]
        if len(probe) >= 2 and probe[:2] == b"\xaa\x55":
            out.append(i)
        elif probe and (set(probe) == {0xFF} or set(probe) == {0x00}):
            out.append(i)
    return out

def walk_sector(region, sec_off, span_end, g):
    """Walk records of one sector. Returns (records, end_pos, torn) where
    end_pos is the region-relative offset just past the last good record and
    torn=True when the walk stopped on a bad/truncated header (vs. erased
    tail or span end)."""
    data = region.data
    records = []
    pos = sec_off + 16
    torn = False
    while True:
        if pos + 8 > span_end:
            if pos < span_end and data[pos:span_end] not in (
                    b"\xff" * (span_end - pos), b"\x00" * (span_end - pos)):
                torn = True
            break
        hdr = data[pos:pos + 8]
        if hdr == b"\xff" * 8:
            break  # erased tail: clean stop
        magic, crc_stored, flags, lens = struct.unpack("<HHHH", hdr)
        if magic != RECORD_MAGIC:
            torn = True
            break
        klen = lens & 0xF
        vlen = lens >> 4
        if klen == 0 or klen > 15:
            torn = True
            break
        key_off = pos + align_up(g, 8)
        val_off = key_off + align_up(g, klen)
        total = align_up(g, 8) + align_up(g, klen) + align_up(g, vlen)
        if pos + total > span_end or val_off + vlen > span_end:
            torn = True
            break
        key = bytes(data[key_off:key_off + klen])
        val = bytes(data[val_off:val_off + vlen])
        records.append({
            "offset": region.base + pos,
            "region": region.name,
            "sector_offset": region.base + sec_off,
            "key_bytes": key,
            "value": val,
            "flags": flags,
            "live": (flags & 1) == 0,
            "crc_stored": crc_stored,
            "crc_computed": record_crc(key, val),
        })
        pos += total
    return records, pos, torn

def parse_regions(regions, align_override=None, sector_align=None):
    """Returns (sectors, records, align_used). Sector spans run to the next
    accepted header or the region end. Alignment is auto-detected by scoring
    each candidate: most CRC-valid records, then most clean sectors.

    sector_align (e.g. 0x1000 for real 4 KB NOR sectors) restricts which
    offsets may host a sector header; pass None for synthetic buffers."""
    aligns = [align_override] if align_override else list(ALIGN_CANDIDATES)
    best = None
    for g in aligns:
        sectors, records = [], []
        for region in regions:
            cands = find_sector_candidates(region, sector_align)
            accepted_end = -1
            for idx, soff in enumerate(cands):
                if soff < accepted_end:
                    continue  # inside the walked extent of a previous sector
                span_end = cands[idx + 1] if idx + 1 < len(cands) else len(region.data)
                recs, end_pos, torn = walk_sector(region, soff, span_end, g)
                sectors.append({
                    "region": region.name,
                    "offset": region.base + soff,
                    "version": u16(region.data, soff + 2),
                    "meta_4_7": region.data[soff + 4:soff + 8].hex(),
                    "seq": u64(region.data, soff + 8),
                    "torn": torn,
                    "n_records": len(recs),
                })
                records.extend(recs)
                accepted_end = end_pos
        crc_ok = sum(1 for r in records if r["crc_stored"] == r["crc_computed"])
        clean = sum(1 for s in sectors if not s["torn"])
        score = (crc_ok, clean, len(records))
        if best is None or score > best[0]:
            best = (score, sectors, records, g)
    _, sectors, records, g = best
    return sectors, records, g

# ------------------------------------------------------------ resolving ----

def resolve_winners(records):
    """Per key: winner = max by (sector sequence, absolute offset).
    Returns ({key_str: winning_record}, ambiguities) where ambiguities lists
    keys whose top-2 candidates share the same sector sequence across
    different sectors — the relative-order guarantee of the firmware between
    two distinct sectors with equal sequence is not established, so the
    winner is flagged rather than silently tie-broken by offset."""
    winners = {}
    per_key = {}
    for r in records:
        try:
            key = r["key_bytes"].decode("ascii")
        except UnicodeDecodeError:
            continue
        cands = per_key.setdefault(key, [])
        cands.append(r)
        cur = winners.get(key)
        rank = (r["_sector_seq"], r["offset"])
        if cur is None or rank >= (cur["_sector_seq"], cur["offset"]):
            winners[key] = r
    ambiguities = []
    for key, cands in per_key.items():
        seqs = {r["_sector_seq"] for r in cands}
        if cands and len(cands) > 1:
            top = max(cands, key=lambda r: (r["_sector_seq"], r["offset"]))
            rivals = [r for r in cands if r is not top
                      and r["_sector_seq"] == top["_sector_seq"]]
            if rivals:
                ambiguities.append({"key": key, "sequence": top["_sector_seq"],
                                    "winner_offset": top["offset"],
                                    "rival_offsets": [r["offset"] for r in rivals]})
    return winners, ambiguities

def _crc_bad_verdict(w):
    return {
        "state": "CRC_BAD",
        "crc_ok": False,
        "crc_stored": w["crc_stored"],
        "crc_computed": w["crc_computed"],
        "raw_live": w["live"],
        "raw_value_hex": w["value"].hex(),
        "offset": w["offset"],
        "detail": "winning record failed CRC-16 check (firmware GetValue rejects with 0xF)",
    }

def verdicts(winners):
    v = {}
    w = winners.get("IsDfDevice")
    if w is None:
        v["IsDfDevice"] = {"state": "ABSENT",
                           "detail": "no live record; compiled default FALSE applies"}
    elif w["crc_stored"] != w["crc_computed"]:
        v["IsDfDevice"] = _crc_bad_verdict(w)
    elif not w["live"]:
        v["IsDfDevice"] = {"state": "ABSENT", "crc_ok": True,
                           "detail": "latest record is a tombstone; compiled default FALSE applies"}
    else:
        val = u32(w["value"], 0) if len(w["value"]) >= 4 else None
        v["IsDfDevice"] = {"state": "LIVE", "value_u32": val,
                           "bool": (val != 0) if val is not None else None,
                           "offset": w["offset"], "crc_ok": True}

    w = winners.get("SsdpUdn")
    if w is None:
        v["SsdpUdn"] = {"state": "ABSENT",
                        "detail": "no live record; firmware generates and stores one at first init"}
    elif w["crc_stored"] != w["crc_computed"]:
        v["SsdpUdn"] = _crc_bad_verdict(w)
    elif not w["live"]:
        v["SsdpUdn"] = {"state": "ABSENT", "crc_ok": True,
                        "detail": "latest record is a tombstone"}
    else:
        raw = w["value"]
        eff = raw.split(b"\x00", 1)[0]
        if len(eff) == 0:
            v["SsdpUdn"] = {"state": "EMPTY", "value_len": len(raw),
                            "offset": w["offset"], "crc_ok": True}
        else:
            v["SsdpUdn"] = {"state": "PRESENT", "value": eff.decode("ascii", "replace"),
                            "value_len": len(raw), "offset": w["offset"], "crc_ok": True}

    w = winners.get("UpdateGauge")
    if w is None:
        v["UpdateGauge"] = {"state": "ABSENT",
                            "detail": "no live record; compiled default TRUE applies"}
    elif w["crc_stored"] != w["crc_computed"]:
        v["UpdateGauge"] = _crc_bad_verdict(w)
    elif not w["live"]:
        v["UpdateGauge"] = {"state": "ABSENT", "crc_ok": True,
                            "detail": "latest record is a tombstone; compiled default TRUE applies"}
    else:
        val = u32(w["value"], 0) if len(w["value"]) >= 4 else None
        v["UpdateGauge"] = {"state": "LIVE", "value_u32": val,
                            "bool": (val != 0) if val is not None else None,
                            "offset": w["offset"], "crc_ok": True}
    return v

# --------------------------------------------------------------- output ----

def fmt_value(val):
    parts = ["hex=" + (val.hex() if val else "(empty)")]
    if len(val) >= 4:
        parts.append("u32=%d" % u32(val, 0))
    if val and all(0x20 <= b < 0x7F for b in val):
        parts.append("ascii=%r" % val.decode("ascii"))
    return " ".join(parts)

def render_text(regions, sectors, records, g, verd, ambiguities=()):
    lines = []
    lines.append("KVS parse: %d region(s), %d sector(s), %d record(s), align=%d"
                 % (len(regions), len(sectors), len(records), g))
    for s in sectors:
        lines.append("  sector @0x%08X (%s) version=%d seq=%d records=%d%s"
                     % (s["offset"], s["region"], s["version"], s["seq"],
                        s["n_records"], " TORN-TAIL" if s["torn"] else ""))
    lines.append("")
    lines.append("--- records (offset order) ---")
    for r in sorted(records, key=lambda r: r["offset"]):
        try:
            key = r["key_bytes"].decode("ascii")
            key = key if key.isprintable() else r["key_bytes"].hex()
        except UnicodeDecodeError:
            key = r["key_bytes"].hex()
        crc_ok = r["crc_stored"] == r["crc_computed"]
        lines.append("0x%08X sector@0x%08X seq=%d key=%r flags=0x%04X %s crc=%s %s"
                     % (r["offset"], r["sector_offset"], r["_sector_seq"], key,
                        r["flags"], "LIVE" if r["live"] else "DEAD",
                        "OK" if crc_ok else "BAD(stored 0x%04X calc 0x%04X)"
                        % (r["crc_stored"], r["crc_computed"]),
                        fmt_value(r["value"])))
    lines.append("")
    lines.append("--- verdicts ---")
    for k in KEYS_OF_INTEREST:
        lines.append("%s: %s" % (k, json.dumps(verd[k], sort_keys=True)))
    if ambiguities:
        lines.append("")
        lines.append("--- ambiguities ---")
        for a in ambiguities:
            lines.append("WARNING: key=%r seq=%d winner=0x%08X rivals=%s"
                         % (a["key"], a["sequence"], a["winner_offset"],
                            [hex(o) for o in a["rival_offsets"]]))
    bad = [r for r in records if r["crc_stored"] != r["crc_computed"]]
    if bad:
        lines.append("WARNING: %d record(s) with bad CRC (parsed structurally; "
                     "firmware would reject them on full read)" % len(bad))
    return "\n".join(lines)

def to_json(regions, sectors, records, g, verd, ambiguities=()):
    out_records = []
    for r in sorted(records, key=lambda r: r["offset"]):
        try:
            key = r["key_bytes"].decode("ascii")
            if not key.isprintable():
                key = None
        except UnicodeDecodeError:
            key = None
        out_records.append({
            "offset": r["offset"], "region": r["region"],
            "sector_offset": r["sector_offset"], "sector_seq": r["_sector_seq"],
            "key": key, "key_hex": r["key_bytes"].hex(),
            "value_hex": r["value"].hex(),
            "value_u32": u32(r["value"], 0) if len(r["value"]) >= 4 else None,
            "value_ascii": r["value"].decode("ascii") if r["value"] and
                           all(0x20 <= b < 0x7F for b in r["value"]) else None,
            "flags": r["flags"], "live": r["live"],
            "crc_stored": r["crc_stored"], "crc_computed": r["crc_computed"],
            "crc_ok": r["crc_stored"] == r["crc_computed"],
        })
    return {"align": g, "sectors": sectors, "records": out_records,
            "verdicts": verd, "ambiguities": list(ambiguities)}

def attach_seqs(sectors, records):
    seq_by_sector = {(s["region"], s["offset"]): s["seq"] for s in sectors}
    for r in records:
        r["_sector_seq"] = seq_by_sector.get((r["region"], r["sector_offset"]), 0)

# ------------------------------------------------------------- selftest ----

def build_record(key, value, live, g, corrupt_crc=False):
    klen, vlen = len(key), len(value)
    lens = (vlen << 4) | klen
    crc = record_crc(key, value)
    if corrupt_crc:
        crc ^= 0x5A5A
    hdr = struct.pack("<HHHH", RECORD_MAGIC, crc, 0 if live else 1, lens)
    rec = hdr + b"\x00" * (align_up(g, 8) - 8)
    rec += key + b"\x00" * (align_up(g, klen) - klen)
    rec += value + b"\x00" * (align_up(g, vlen) - vlen)
    return rec

def build_sector(seq, version, recs, size, g, torn_tail=b""):
    hdr = struct.pack("<HH", SECTOR_MAGIC, version) + b"\x00" * 4 + struct.pack("<Q", seq)
    body = hdr + b"".join(recs) + torn_tail
    assert len(body) <= size
    return body + b"\xff" * (size - len(body))

def selftest():
    g = 4
    u32v = lambda n: struct.pack("<I", n)
    sec1 = build_sector(1, 4, [
        build_record(b"IsDfDevice", u32v(1), live=False, g=g),   # aborted write
        build_record(b"IsDfDevice", u32v(0), live=True, g=g),    # older live 0
        build_record(b"SsdpUdn", b"SOME-UDN-VALUE", live=True, g=g),
        build_record(b"UpdateGauge", u32v(0), live=False, g=g),  # tombstone
    ], 512, g)
    sec2 = build_sector(2, 4, [
        build_record(b"IsDfDevice", u32v(1), live=True, g=g),    # newest: wins
        build_record(b"SsdpUdn", b"", live=True, g=g),           # newest: EMPTY
        build_record(b"UpdateGauge", u32v(1), live=True, g=g),   # supersedes tombstone
        build_record(b"TombKey", u32v(7), live=False, g=g),      # only a tombstone
    ], 512, g, torn_tail=b"\xaa\x55\x01\x02")                    # torn tail
    erased = b"\xff" * 512
    blob = sec1 + sec2 + erased
    region = Region("selftest", 0x60F00000, blob)

    sectors, records, used_g = parse_regions([region])
    attach_seqs(sectors, records)
    winners, ambiguities = resolve_winners(records)
    verd = verdicts(winners)

    fails = []
    def check(name, cond):
        print("  [%s] %s" % ("ok" if cond else "FAIL", name))
        if not cond:
            fails.append(name)

    print("selftest: align auto-detected = %d, sectors = %d, records = %d"
          % (used_g, len(sectors), len(records)))
    check("alignment 4 detected", used_g == 4)
    check("2 sectors found (erased sector has no header)", len(sectors) == 2)
    check("8 records walked", len(records) == 8)
    check("all CRCs valid", all(r["crc_stored"] == r["crc_computed"] for r in records))
    check("sector 2 marked torn", sectors[1]["torn"] is True)
    check("IsDfDevice LIVE 1 (newest sector wins)",
          verd["IsDfDevice"].get("state") == "LIVE" and verd["IsDfDevice"].get("value_u32") == 1)
    check("SsdpUdn EMPTY (newest record, value_len 0)",
          verd["SsdpUdn"].get("state") == "EMPTY")
    check("UpdateGauge LIVE 1 (live supersedes tombstone)",
          verd["UpdateGauge"].get("state") == "LIVE" and verd["UpdateGauge"].get("value_u32") == 1)
    tk = winners.get("TombKey")
    check("TombKey winner is the tombstone (reads absent)",
          tk is not None and tk["live"] is False)

    # CRC-failure path: corrupt one value byte, record must still parse.
    bad = bytearray(blob)
    pos = bytes(bad).find(b"SOME-UDN-VALUE")
    bad[pos] ^= 0xFF
    _, recs2, g2 = parse_regions([Region("selftest-bad", 0x60F00000, bytes(bad))])
    target = [r for r in recs2 if r["key_bytes"] == b"SsdpUdn"]
    check("corrupted record still parsed, CRC flagged bad",
          len(target) == 2 and any(r["crc_stored"] != r["crc_computed"] for r in target))

    # False-positive guard: a 0xABCD sequence embedded inside a record area
    # must not be accepted as a sector header when sector alignment applies
    # (real NOR sectors are 4 KB aligned; here 512 B synthetic alignment).
    fp = bytearray(blob)
    ins = 40  # inside sector 1, NOT a multiple of the 512 B sector stride
    fp[ins:ins] = b"\xcd\xab\x02\x00\x00\x00\x00\x00" + b"\x00" * 8
    sectors_fp, _, _ = parse_regions([Region("selftest-fp", 0x60F00000, bytes(fp))],
                                     align_override=4, sector_align=512)
    check("0xABCD inside payload not accepted as header (sector_align)",
          all(s["offset"] != 0x60F00000 + ins for s in sectors_fp))

    # sector_sequence collision across distinct sectors -> ambiguity flag
    def fake_rec(key, value, seq, off):
        return {"key_bytes": key, "value": value, "live": True,
                "_sector_seq": seq, "offset": off,
                "crc_stored": 0, "crc_computed": 0}
    r_a = fake_rec(b"CollideKey", b"AAAA", 7, 0x100)
    r_b = fake_rec(b"CollideKey", b"BBBB", 7, 0x300)  # same seq, other sector
    win_c, amb_c = resolve_winners([r_a, r_b])
    check("sequence collision flagged ambiguous", len(amb_c) == 1 and
          amb_c[0]["key"] == "CollideKey")
    r_c = fake_rec(b"CollideKey", b"CCCC", 8, 0x900)  # higher seq wins cleanly
    win_d, amb_d = resolve_winners([r_a, r_c])
    check("distinct sequences resolve cleanly", len(amb_d) == 0 and
          win_d["CollideKey"]["value"] == r_c["value"])

    # Bad-CRC winning record must NOT emit LIVE verdict.
    bad_win = build_sector(9, 4, [
        build_record(b"IsDfDevice", u32v(1), live=True, g=g, corrupt_crc=True),
    ], 512, g)
    s_bw, r_bw, _ = parse_regions([Region("bw", 0x60940000, bad_win)])
    attach_seqs(s_bw, r_bw)
    w_bw, _ = resolve_winners(r_bw)
    v_bw = verdicts(w_bw)
    check("bad-CRC winning record emits CRC_BAD verdict",
          v_bw["IsDfDevice"].get("state") == "CRC_BAD" and
          v_bw["IsDfDevice"].get("crc_ok") is False)

    # Ambiguities surface in both render_text() and to_json().
    txt_amb = render_text([region], sectors, records, used_g, verd, amb_c)
    js_amb = to_json([region], sectors, records, used_g, verd, amb_c)
    check("ambiguities included in text and JSON outputs",
          "--- ambiguities ---" in txt_amb and len(js_amb.get("ambiguities", [])) == 1)

    # CLI path enforces default 0x1000 sector_align to ignore embedded 0xABCD bytes.
    embedded_payload = u32v(1) + b"\xcd\xab\x02\x00\x00\x00\x00\x00" + b"\xff" * 64
    cli_sec = build_sector(1, 4, [build_record(b"IsDfDevice", embedded_payload, True, g)], 0x1000, g)
    with tempfile.TemporaryDirectory() as td:
        dump_path = os.path.join(td, "kvs.bin")
        json_path = os.path.join(td, "out.json")
        with open(dump_path, "wb") as fh:
            fh.write(cli_sec)
        with contextlib.redirect_stdout(io.StringIO()):
            rc_cli = main(["--region", "%s@0x60940000" % dump_path, "--json", json_path])
        with open(json_path, "r") as fh:
            cli_out = json.load(fh)
        check("CLI default sector_align=0x1000 ignores embedded 0xABCD",
              rc_cli == 0 and len(cli_out["sectors"]) == 1 and
              cli_out["sectors"][0]["torn"] is False)
        with contextlib.redirect_stdout(io.StringIO()):
            rc_raw = main(["--region", "%s@0x60940000" % dump_path,
                           "--sector-align", "0", "--json", json_path])
        with open(json_path, "r") as fh:
            raw_out = json.load(fh)
        check("CLI --sector-align 0 disables alignment guard",
              rc_raw == 0 and len(raw_out["sectors"]) == 2 and
              raw_out["sectors"][0]["torn"] is True)

    print("SELFTEST " + ("PASS" if not fails else "FAIL: %s" % ", ".join(fails)))
    return 0 if not fails else 1

# ----------------------------------------------------------------- main ----

def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse Stadia KVS NOR dumps.")
    ap.add_argument("--region", action="append", default=[],
                    metavar="FILE@0xOFFSET",
                    help="raw dump file and the NOR address of its first byte "
                         "(repeatable)")
    ap.add_argument("--json", metavar="PATH",
                    help="write JSON results to PATH ('-' = stdout, replaces text)")
    ap.add_argument("--align", type=int, choices=ALIGN_CANDIDATES,
                    help="force store granularity instead of auto-detect")
    ap.add_argument("--sector-align", type=lambda s: int(s, 0), default=0x1000,
                    metavar="BYTES",
                    help="required byte alignment for sector headers in NOR dumps; "
                         "pass 0 to disable (default: 0x1000)")
    ap.add_argument("--selftest", action="store_true",
                    help="build synthetic dumps, parse them back, assert verdicts")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not args.region:
        ap.error("need at least one --region (or --selftest)")

    regions = []
    for spec in args.region:
        if "@" in spec:
            path, off = spec.rsplit("@", 1)
            base = int(off, 0)
        else:
            path, base = spec, 0
        with open(path, "rb") as fh:
            regions.append(Region(path, base, fh.read()))

    sector_align = args.sector_align or None
    sectors, records, g = parse_regions(regions, args.align, sector_align=sector_align)
    attach_seqs(sectors, records)
    winners, ambiguities = resolve_winners(records)
    verd = verdicts(winners)

    if args.json == "-":
        print(json.dumps(to_json(regions, sectors, records, g, verd, ambiguities), indent=2))
        return 0
    print(render_text(regions, sectors, records, g, verd, ambiguities))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(regions, sectors, records, g, verd, ambiguities), fh, indent=2)
        print("JSON written to %s" % args.json)
    return 0

if __name__ == "__main__":
    sys.exit(main())
