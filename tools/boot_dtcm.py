#!/usr/bin/env python3
"""One-command DTCM bootloader for Google Stadia Controller (i.MX RT1061 SDP).

Checks NXP BootROM SDP HAB security status (1fc9:0135), optionally runs the
temporary ROMC unlock via `nxp-sdp-overrun` if HAB is Closed (0x12343412),
downloads a bare-metal IVT image to DTCM (0x20000000), jumps to 0x20000400,
and optionally attaches to the USB CDC-ACM debug console.
"""

import argparse
import glob
import os
import select
import struct
import subprocess
import sys
import termios
import time
import tty

SDP_VID = 0x1FC9
SDP_PID = 0x0135

HAB_CLOSED = 0x12343412
HAB_OPEN = 0x56787856

SDP_CMD_WRITE_FILE = 0x0404
SDP_CMD_ERROR_STATUS = 0x0505
SDP_CMD_JUMP_ADDRESS = 0x0B0B

DEFAULT_LOAD_ADDR = 0x20000000
DEFAULT_IVT_OFFSET = 0x400
IVT_HEADER_MAGIC = 0x412000D1


def build_sdp_cmd(cmd: int, addr: int = 0, fmt: int = 0, count: int = 0, data: int = 0) -> bytes:
    """Build a 17-byte HID Report ID 1 SDP command packet (1B ID + 16B SDP command)."""
    return struct.pack(">BHIBIIB", 1, cmd, addr, fmt, count, data, 0)


def split_write_chunks(blob: bytes, chunk_size: int = 1024):
    """Yield 1025-byte HID Report ID 2 data packets (final chunk zero-padded)."""
    for off in range(0, len(blob), chunk_size):
        chunk = blob[off : off + chunk_size].ljust(chunk_size, b"\x00")
        yield bytes([2]) + chunk


def validate_dtcm_image(blob: bytes, load_addr: int = DEFAULT_LOAD_ADDR, ivt_offset: int = DEFAULT_IVT_OFFSET):
    """Verify the IVT header and boot_data bounds before uploading to DTCM."""
    if len(blob) < ivt_offset + 0x2C:
        raise ValueError(f"Image too small ({len(blob)} B < 0x{ivt_offset + 0x2C:x})")
    hdr, entry, _r1, _dcd, boot_data_ptr, self_ptr, _csf, _r2 = struct.unpack_from("<8I", blob, ivt_offset)
    if hdr != IVT_HEADER_MAGIC:
        raise ValueError(f"Bad IVT header 0x{hdr:08x} at +0x{ivt_offset:x} (expected 0x{IVT_HEADER_MAGIC:08x})")
    expected_self = load_addr + ivt_offset
    if self_ptr != expected_self:
        raise ValueError(f"IVT self=0x{self_ptr:08x} does not match 0x{expected_self:08x}")
    bd_off = boot_data_ptr - load_addr
    if bd_off < 0 or bd_off + 12 > len(blob):
        raise ValueError(f"boot_data pointer 0x{boot_data_ptr:08x} outside image")
    bd_start, bd_len, _plugin = struct.unpack_from("<3I", blob, bd_off)
    if bd_start != load_addr:
        raise ValueError(f"boot_data.start=0x{bd_start:08x} != 0x{load_addr:08x}")
    if len(blob) > bd_len:
        raise ValueError(f"Image size ({len(blob)} B) exceeds boot_data.length ({bd_len} B)")
    return {"entry": entry, "self": self_ptr, "boot_data_len": bd_len, "size": len(blob)}


def _import_hid():
    try:
        import hidraw as hid  # type: ignore
        return hid
    except ModuleNotFoundError:
        import hid  # type: ignore
        return hid


def sdp_error_status(dev) -> tuple[int, int]:
    dev.write(build_sdp_cmd(SDP_CMD_ERROR_STATUS))
    r3 = bytes(dev.read(65, timeout_ms=2000))
    r4 = bytes(dev.read(65, timeout_ms=2000))
    if len(r3) < 5 or r3[0] != 3:
        raise RuntimeError(f"Unexpected SDP Report 3: {r3[:8].hex()}")
    if len(r4) < 5 or r4[0] != 4:
        raise RuntimeError(f"Unexpected SDP Report 4: {r4[:8].hex()}")
    hab = struct.unpack_from(">I", r3, 1)[0]
    status = struct.unpack_from(">I", r4, 1)[0]
    return hab, status


def sdp_write_file(dev, addr: int, blob: bytes) -> int:
    dev.write(build_sdp_cmd(SDP_CMD_WRITE_FILE, addr=addr, count=len(blob)))
    for pkt in split_write_chunks(blob):
        dev.write(pkt)
    r3 = bytes(dev.read(65, timeout_ms=5000))
    r4 = bytes(dev.read(65, timeout_ms=5000))
    if len(r3) < 5 or len(r4) < 5:
        raise RuntimeError(f"Short SDP WRITE_FILE status (r3={len(r3)} r4={len(r4)})")
    status = struct.unpack_from(">I", r4, 1)[0]
    if status != 0x88888888:
        raise RuntimeError(f"SDP WRITE_FILE failed: status=0x{status:08x}")
    return status


def sdp_jump_address(dev, ivt_addr: int) -> None:
    dev.write(build_sdp_cmd(SDP_CMD_JUMP_ADDRESS, addr=ivt_addr))
    try:
        r3 = bytes(dev.read(65, timeout_ms=1000))
        if len(r3) >= 5 and r3[0] == 3:
            hab = struct.unpack_from(">I", r3, 1)[0]
            print(f"SDP JUMP_ADDRESS ack: hab=0x{hab:08x}")
    except Exception:
        # Device disconnects USB immediately on successful jump
        pass


def find_overrun_script(explicit: str | None) -> str | None:
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "..", "..", "nxp-sdp-overrun", "main.py"),
        os.path.join(os.getcwd(), "nxp-sdp-overrun", "main.py"),
        os.path.join(os.getcwd(), "..", "nxp-sdp-overrun", "main.py"),
    ]
    for path in candidates:
        norm = os.path.normpath(path)
        if os.path.isfile(norm):
            return norm
    return None


def find_cdc_port(explicit: str | None, wait_sec: float = 6.0) -> str | None:
    deadline = time.monotonic() + wait_sec
    while time.monotonic() < deadline:
        if explicit:
            if os.path.exists(explicit):
                return explicit
        else:
            matches = sorted(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/ttyACM*"))
            if matches:
                return matches[0]
        time.sleep(0.2)
    return None


def run_console(port: str) -> int:
    print(f"Attaching to CDC console {port} (Ctrl-C to exit)...")
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    old_stdin = None
    try:
        tty.setraw(fd, when=termios.TCSANOW)
        if sys.stdin.isatty():
            old_stdin = termios.tcgetattr(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        while True:
            rlist = [fd]
            if sys.stdin.isatty():
                rlist.append(sys.stdin.fileno())
            ready, _, _ = select.select(rlist, [], [], 0.2)
            if fd in ready:
                try:
                    chunk = os.read(fd, 512)
                except OSError:
                    print("\n[CDC disconnected]")
                    break
                if not chunk:
                    print("\n[CDC EOF]")
                    break
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            if sys.stdin.isatty() and sys.stdin.fileno() in ready:
                data = os.read(sys.stdin.fileno(), 64)
                if data:
                    os.write(fd, data)
    except KeyboardInterrupt:
        print("\n[Console closed]")
    finally:
        if old_stdin is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_stdin)
        try:
            termios.tcflush(fd, termios.TCIOFLUSH)
        except OSError:
            pass
        os.close(fd)
    return 0


def run_selftest() -> int:
    # 1. Verify SDP command framing (Report ID 1 + big-endian 16-byte command)
    cmd_err = build_sdp_cmd(SDP_CMD_ERROR_STATUS)
    assert len(cmd_err) == 17 and cmd_err[:3] == b"\x01\x05\x05", f"bad err cmd: {cmd_err.hex()}"
    cmd_wr = build_sdp_cmd(SDP_CMD_WRITE_FILE, addr=0x20000000, count=0x1000)
    assert len(cmd_wr) == 17 and cmd_wr[3:7] == b"\x20\x00\x00\x00" and cmd_wr[8:12] == b"\x00\x00\x10\x00"
    cmd_jmp = build_sdp_cmd(SDP_CMD_JUMP_ADDRESS, addr=0x20000400)
    assert len(cmd_jmp) == 17 and cmd_jmp[:7] == b"\x01\x0b\x0b\x20\x00\x04\x00"

    # 2. Verify chunk splitting (Report ID 2 prefix, 1024-byte padded chunks)
    chunks = list(split_write_chunks(b"A" * 2050, chunk_size=1024))
    assert len(chunks) == 3
    assert len(chunks[0]) == 1025 and chunks[0][0] == 2
    assert len(chunks[2]) == 1025 and chunks[2][:4] == b"\x02AA\x00"

    # 3. Verify synthetic DTCM IVT validation (accepts valid, rejects oversized/bad magic)
    img = bytearray(0x600)
    struct.pack_into(
        "<8I",
        img,
        0x400,
        IVT_HEADER_MAGIC,
        0x20000000,
        0,
        0,
        0x20000420,
        0x20000400,
        0,
        0,
    )
    struct.pack_into("<3I", img, 0x420, 0x20000000, 0x18000, 0)
    info = validate_dtcm_image(bytes(img))
    assert info["entry"] == 0x20000000 and info["boot_data_len"] == 0x18000

    bad = bytearray(img)
    bad[0x400] ^= 0xFF
    try:
        validate_dtcm_image(bytes(bad))
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for bad IVT magic")

    print("boot_dtcm.py selftest: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Unlock (ROMC), load, and boot a DTCM image via NXP SDP")
    parser.add_argument("--bin", dest="bin_path", help="Path to DTCM binary (default: auto-detect stadia_hello.bin)")
    parser.add_argument("--addr", type=lambda s: int(s, 0), default=DEFAULT_LOAD_ADDR, help="Load address (default 0x20000000)")
    parser.add_argument("--ivt-offset", type=lambda s: int(s, 0), default=DEFAULT_IVT_OFFSET, help="IVT offset (default 0x400)")
    parser.add_argument("--overrun-script", help="Path to nxp-sdp-overrun/main.py (auto-detected if omitted)")
    parser.add_argument("--no-unlock", action="store_true", help="Do not invoke nxp-sdp-overrun even if HAB is Closed")
    parser.add_argument("--console", action="store_true", help="Attach to USB CDC-ACM console after jumping")
    parser.add_argument("--port", help="Explicit serial port for --console (default: auto-detect /dev/cu.usbmodem*)")
    parser.add_argument("--selftest", action="store_true", help="Run offline unit tests and exit")
    args = parser.parse_args()

    if args.selftest:
        return run_selftest()

    bin_path = args.bin_path
    if not bin_path:
        here = os.path.dirname(os.path.abspath(__file__))
        for cand in [
            os.path.join(here, "..", "firmware", "stadia-ram-hello", "build", "stadia_hello.bin"),
            os.path.join(here, "..", "..", "stadia-ram-hello", "build", "stadia_hello.bin"),
            os.path.join(os.getcwd(), "build", "stadia_hello.bin"),
        ]:
            norm = os.path.normpath(cand)
            if os.path.isfile(norm):
                bin_path = norm
                break
    if not bin_path or not os.path.isfile(bin_path):
        print("Error: DTCM binary not found; pass --bin <path/to/stadia_hello.bin>", file=sys.stderr)
        return 1

    with open(bin_path, "rb") as f:
        blob = f.read()
    info = validate_dtcm_image(blob, load_addr=args.addr, ivt_offset=args.ivt_offset)
    print(f"Image OK: {bin_path} ({info['size']} B, IVT=0x{info['self']:08x}, limit={info['boot_data_len']} B)")

    hid = _import_hid()
    dev = hid.device()
    try:
        dev.open(SDP_VID, SDP_PID)
    except OSError as exc:
        print(f"Error: NXP SDP device {SDP_VID:04x}:{SDP_PID:04x} not found ({exc})", file=sys.stderr)
        print("Hold Options + Assistant + A + Y while plugging USB-C to enter BootROM SDP.", file=sys.stderr)
        return 2

    try:
        hab, st = sdp_error_status(dev)
        print(f"SDP initial status: hab=0x{hab:08x} status=0x{st:08x}")
        if hab == HAB_CLOSED:
            if args.no_unlock:
                print("Error: HAB is Closed (0x12343412) and --no-unlock was specified.", file=sys.stderr)
                return 3
            overrun = find_overrun_script(args.overrun_script)
            if not overrun:
                print("Error: HAB is Closed and nxp-sdp-overrun/main.py was not found (use --overrun-script).", file=sys.stderr)
                return 3
            dev.close()
            print(f"HAB Closed -> running temporary ROMC unlock: {overrun}")
            res = subprocess.run([sys.executable, overrun], check=False)
            if res.returncode != 0:
                print(f"Error: nxp-sdp-overrun exited with {res.returncode}", file=sys.stderr)
                return res.returncode
            time.sleep(0.35)
            dev = hid.device()
            dev.open(SDP_VID, SDP_PID)
            hab, st = sdp_error_status(dev)
            print(f"SDP post-unlock status: hab=0x{hab:08x} status=0x{st:08x}")
            if hab != HAB_OPEN:
                print(f"Error: Expected HAB Open (0x{HAB_OPEN:08x}), got 0x{hab:08x}", file=sys.stderr)
                return 4
        elif hab != HAB_OPEN:
            print(f"Warning: Unexpected HAB value 0x{hab:08x}; continuing anyway...")

        print(f"Uploading {len(blob)} bytes to 0x{args.addr:08x}...")
        sdp_write_file(dev, args.addr, blob)
        ivt_addr = args.addr + args.ivt_offset
        print(f"Jumping to IVT 0x{ivt_addr:08x}...")
        sdp_jump_address(dev, ivt_addr)
    finally:
        try:
            dev.close()
        except Exception:
            pass

    print("Booted successfully!")
    if args.console:
        port = find_cdc_port(args.port)
        if not port:
            print("Warning: USB CDC-ACM port did not appear within timeout.", file=sys.stderr)
            return 5
        return run_console(port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
