#!/usr/bin/env python3
"""Extract Broadcom BCM43458F .hcd patchram blob from a Stadia Controller firmware dump.

Searches for the HCI Write_RAM + BRCMcfgS header, walks length-framed HCI vendor
packets through Launch_RAM (0xFC4E), and emits a C header (`bcm43458f_hcd.h`)
without redistributing copyrighted firmware binaries.
"""

import argparse
import os
import struct
import sys

HCD_MAGIC = b"\x4c\xfc\x46\x00\x00\x22\x00BRCMcfgS"


def extract_hcd_bytes(blob: bytes):
    start = blob.find(HCD_MAGIC)
    if start < 0:
        raise ValueError("BCM43458F HCD signature (4C FC ... BRCMcfgS) not found")
    pos = start
    pkts = 0
    while pos + 3 <= len(blob):
        opcode, plen = struct.unpack_from("<HB", blob, pos)
        end = pos + 3 + plen
        if end > len(blob):
            raise ValueError(f"Truncated HCD packet at offset 0x{pos:x}")
        pkts += 1
        pos = end
        if opcode == 0xFC4E:  # Launch_RAM
            return start, blob[start:pos], pkts
        if (opcode >> 10) != 0x3F:  # Must remain vendor-specific OGF 0x3F
            raise ValueError(f"Unexpected non-vendor HCI opcode 0x{opcode:04x} at 0x{pos:x}")
    raise ValueError("Reached EOF before Launch_RAM (0xFC4E)")


def format_c_header(hcd: bytes, source_label: str, offset: int, pkts: int) -> str:
    lines = [
        f"/* Extracted from {source_label} 0x{offset:x}..0x{offset + len(hcd):x} "
        f"({len(hcd)} B, {pkts} HCI packets) */",
        "#pragma once",
        "#include <stdint.h>",
        "",
        f"static const uint32_t k_bcm43458f_hcd_len = {len(hcd)}u;",
        f"static const uint8_t k_bcm43458f_hcd[{len(hcd)}] = {{",
    ]
    for i in range(0, len(hcd), 16):
        row = ", ".join(f"0x{b:02X}u" for b in hcd[i : i + 16])
        comma = "," if i + 16 < len(hcd) else ""
        lines.append(f"    {row}{comma}")
    lines.append("};")
    lines.append("")
    return "\n".join(lines)


def run_selftest() -> int:
    # Build synthetic 3-packet HCD (Write_RAM + BRCMcfgS, Write_RAM, Launch_RAM)
    p1_payload = b"\x00\x00\x22\x00BRCMcfgS" + b"\x00" * (0x46 - 12)
    p1 = struct.pack("<HB", 0xFC4C, len(p1_payload)) + p1_payload
    p2 = struct.pack("<HB", 0xFC4C, 4) + b"\x11\x22\x33\x44"
    p3 = struct.pack("<HB", 0xFC4E, 4) + b"\xFF\xFF\xFF\xFF"
    fake_fw = b"\xAA" * 64 + p1 + p2 + p3 + b"\xBB" * 32

    off, hcd, pkts = extract_hcd_bytes(fake_fw)
    assert off == 64, f"expected offset 64, got {off}"
    assert pkts == 3, f"expected 3 packets, got {pkts}"
    assert hcd == p1 + p2 + p3, "extracted bytes mismatch"

    hdr = format_c_header(hcd, "synthetic.bin", off, pkts)
    assert f"k_bcm43458f_hcd_len = {len(hcd)}u;" in hdr
    assert f"k_bcm43458f_hcd[{len(hcd)}]" in hdr

    try:
        extract_hcd_bytes(b"\x00" * 128)
        raise AssertionError("expected ValueError on missing magic")
    except ValueError:
        pass

    print("SELFTEST OK (4 checks)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract BCM43458F .hcd patchram into C header.")
    ap.add_argument("firmware", nargs="?", help="Path to local slot_a_bruce.bin (or gotham) dump")
    ap.add_argument("-o", "--out", default="bcm43458f_hcd.h", help="Output C header path")
    ap.add_argument("--selftest", action="store_true", help="Run offline unit tests")
    args = ap.parse_args()

    if args.selftest:
        return run_selftest()
    if not args.firmware:
        ap.error("firmware path required unless --selftest is set")

    with open(args.firmware, "rb") as f:
        blob = f.read()
    off, hcd, pkts = extract_hcd_bytes(blob)
    hdr = format_c_header(hcd, os.path.basename(args.firmware), off, pkts)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(hdr)
    print(f"Extracted {len(hcd)} B ({pkts} HCI packets) from 0x{off:x} -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
