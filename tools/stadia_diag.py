#!/usr/bin/env python3
"""stadia_diag.py - Strictly read-only USB EP0 diagnostic utility for the
Google Stadia Controller (18d1:9400) in gotham or bruce mode.

Avoids all state-changing requests (0x80 DisableCharging, 0x82 EnterShippingMode,
0x85 RebootFromUsbVendor, 0x86 shipping syscall, and 0x8b bulk task wake).

Supports:
  --poll-battery   Trigger UpdateGauge via bRequest 0x83 before reading 0x84
  --redact         Mask USB serial suffix and SsdpUdn UUID for public sharing
  --json           Emit machine-readable JSON output
  --selftest       Run offline parser and classifier unit tests (no hardware/pyusb)
"""

import argparse
import json
import struct
import sys
import time

STADIA_VID = 0x18D1
STADIA_PID = 0x9400
BRUCE_BUILD_THRESHOLD = 320480  # <= 320480: gotham, > 320480: bruce

BM_REQ_CLASS_IFACE_IN = 0xA1
BM_REQ_CLASS_IFACE_OUT = 0x21

REQ_BUILD_INFO = 0x81
REQ_UPDATE_GAUGE = 0x83
REQ_BATTERY_SOC = 0x84
REQ_SSDP_UDN = 0x87
REQ_SKU = 0x88
REQ_MODEL_ID = 0x89
REQ_SERIAL = REQ_SSDP_UDN  # legacy alias preserved for callers
REQ_MFG_DATE = REQ_SKU
REQ_DEVICE_COLOR = REQ_MODEL_ID
REQ_PROV_STATE = 0x8A
REQ_UNLOCK_STATUS = 0x8C

PROVISIONING_STATES = {
    0: "MissingProvisioningData",
    1: "NeedsFdr",
    2: "FailedToReadFuses",
    3: "ReadyForDeveloperUse",
    4: "ReadyForInternalUserUse",
    5: "ReadyForEndUserUse",
}


def classify_firmware_family(build_number):
    """Classify Stadia firmware family using Google flasher threshold (<= 320480)."""
    return "gotham" if build_number <= BRUCE_BUILD_THRESHOLD else "bruce"


def classify_hardware_stage(serial):
    """Classify hardware revision stage (EVT/DVT/PVT) from serial prefix."""
    if not serial:
        return "UNKNOWN"
    prefix2 = serial[:2]
    if prefix2 in ("91", "92", "93", "94"):
        return "EVT"
    if prefix2 in ("95", "96", "97"):
        return "DVT"
    if prefix2 == "98" and len(serial) >= 4 and serial[:4].isdigit() and int(serial[:4]) < 9809:
        return "DVT"
    return "PVT"


def decode_cstr(raw):
    """Decode an ASCII C-string buffer trimmed at first NUL byte."""
    if not raw:
        return ""
    nul = raw.find(b"\x00")
    if nul != -1:
        raw = raw[:nul]
    return raw.decode("ascii", errors="replace").strip()


def redact_identifiers(serial, ssdp_udn):
    """Mask device-unique suffix of serial and SsdpUdn UUID for safe sharing."""
    if serial:
        masked_serial = (serial[:-4] + "XXXX") if len(serial) > 4 else ("X" * len(serial))
    else:
        masked_serial = ""
    if ssdp_udn and "-" in ssdp_udn:
        parts = ssdp_udn.split("-")
        masked_udn = "-".join([parts[0]] + ["X" * len(p) for p in parts[1:]])
    elif ssdp_udn:
        masked_udn = (ssdp_udn[:4] + "X" * (len(ssdp_udn) - 4)) if len(ssdp_udn) > 4 else ("X" * len(ssdp_udn))
    else:
        masked_udn = ""
    return masked_serial, masked_udn


def decode_build_info_reply(raw):
    """Parse bRequest 0x81 payload: (build_number, board_rev) <II."""
    if len(raw) >= 8:
        build_number, board_rev = struct.unpack_from("<II", raw, 0)
    elif len(raw) >= 4:
        build_number = struct.unpack_from("<I", raw, 0)[0]
        board_rev = None
    else:
        raise ValueError(f"0x81 reply too short ({len(raw)} B)")
    return {
        "build_number": build_number,
        "board_rev": board_rev,
        "firmware_family": classify_firmware_family(build_number),
    }


def decode_battery_reply(raw):
    """Parse bRequest 0x84 payload: uint16_le percentage."""
    if len(raw) < 2:
        raise ValueError(f"0x84 reply too short ({len(raw)} B)")
    soc = struct.unpack_from("<H", raw, 0)[0]
    return soc


def decode_provisioning_reply(raw):
    """Parse bRequest 0x8a payload (ASCII name in bruce/gotham, or uint32 code fallback)."""
    text = decode_cstr(raw)
    if text and all(32 <= ord(ch) < 127 for ch in text):
        rev_map = {v: k for k, v in PROVISIONING_STATES.items()}
        return {"state_name": text, "state_code": rev_map.get(text)}
    if len(raw) == 4:
        code = struct.unpack_from("<I", raw, 0)[0]
        return {"state_name": PROVISIONING_STATES.get(code, f"Unknown({code})"), "state_code": code}
    raise ValueError(f"Unrecognized 0x8a reply ({raw.hex()})")


def decode_unlock_reply(raw):
    """Parse bRequest 0x8c payload: (vendor_usb_task_active, unlock_level) <II."""
    if len(raw) < 8:
        raise ValueError(f"0x8c reply too short ({len(raw)} B)")
    active, unlock_level = struct.unpack_from("<II", raw, 0)
    return {
        "vendor_usb_task_active": bool(active),
        "raw_active": active,
        "unlock_level": unlock_level,
        "unlocked": unlock_level != 0,
    }


def _find_vendor_interface(dev):
    """Locate the bInterfaceClass=0xFF vendor interface number (default 2)."""
    try:
        cfg = dev.get_active_configuration()
        for intf in cfg:
            if intf.bInterfaceClass == 0xFF:
                return intf.bInterfaceNumber
    except Exception:
        pass
    return 2


def query_controller(poll_battery=False, redact=False):
    """Query all read-only EP0 class/vendor diagnostic fields from a connected unit."""
    try:
        import usb.core  # type: ignore
        import usb.util  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "pyusb is required for live hardware queries (install via `pip install pyusb`)."
        ) from exc

    dev = usb.core.find(idVendor=STADIA_VID, idProduct=STADIA_PID)
    if dev is None:
        raise RuntimeError(f"No Stadia Controller ({STADIA_VID:04x}:{STADIA_PID:04x}) found on USB.")

    try:
        usb_serial = (dev.serial_number or "").strip()
    except Exception:
        usb_serial = ""
    hardware_stage = classify_hardware_stage(usb_serial)

    iface = _find_vendor_interface(dev)
    detached = False
    try:
        if dev.is_kernel_driver_active(iface):
            dev.detach_kernel_driver(iface)
            detached = True
    except (NotImplementedError, usb.core.USBError):
        pass

    try:
        usb.util.claim_interface(dev, iface)

        def ctrl_in(req, length=64):
            return bytes(dev.ctrl_transfer(BM_REQ_CLASS_IFACE_IN, req, 0, iface, length, timeout=1500))

        build_info = decode_build_info_reply(ctrl_in(REQ_BUILD_INFO, 8))
        ssdp_udn = decode_cstr(ctrl_in(REQ_SSDP_UDN, 64))
        sku = decode_cstr(ctrl_in(REQ_SKU, 64))
        model_id = decode_cstr(ctrl_in(REQ_MODEL_ID, 64))
        prov = decode_provisioning_reply(ctrl_in(REQ_PROV_STATE, 64))
        unlock = decode_unlock_reply(ctrl_in(REQ_UNLOCK_STATUS, 8))

        if poll_battery:
            dev.ctrl_transfer(BM_REQ_CLASS_IFACE_OUT, REQ_UPDATE_GAUGE, 0, iface, None, timeout=1500)
            time.sleep(0.5)
        battery_soc = decode_battery_reply(ctrl_in(REQ_BATTERY_SOC, 8))

        if redact:
            usb_serial, ssdp_udn = redact_identifiers(usb_serial, ssdp_udn)

        return {
            "usb_id": f"{STADIA_VID:04x}:{STADIA_PID:04x}",
            "interface": iface,
            "serial": usb_serial,
            "hardware_stage": hardware_stage,
            "ssdp_udn": ssdp_udn,
            "sku": sku,
            "model_id": model_id,
            "build_number": build_info["build_number"],
            "board_rev": build_info["board_rev"],
            "firmware_family": build_info["firmware_family"],
            "provisioning_state": prov["state_name"],
            "provisioning_code": prov["state_code"],
            "battery_soc_percent": battery_soc,
            "battery_polled": poll_battery,
            "vendor_usb_task_active": unlock["vendor_usb_task_active"],
            "unlock_level": f"0x{unlock['unlock_level']:08x}",
            "unlocked": unlock["unlocked"],
            "redacted": redact,
        }
    finally:
        try:
            usb.util.release_interface(dev, iface)
        except Exception:
            pass
        if detached:
            try:
                dev.attach_kernel_driver(iface)
            except Exception:
                pass


def run_selftest():
    """Offline self-tests covering all EP0 parsers and classifiers."""
    checks = 0

    assert classify_firmware_family(235551) == "gotham"; checks += 1
    assert classify_firmware_family(316382) == "gotham"; checks += 1
    assert classify_firmware_family(320480) == "gotham"; checks += 1
    assert classify_firmware_family(337784) == "bruce"; checks += 1

    assert classify_hardware_stage("92010ABC") == "EVT"; checks += 1
    assert classify_hardware_stage("96010ABC") == "DVT"; checks += 1
    assert classify_hardware_stage("98081234") == "DVT"; checks += 1
    assert classify_hardware_stage("98091234") == "PVT"; checks += 1
    assert classify_hardware_stage("9C020YCAC6") == "PVT"; checks += 1

    ms, mu = redact_identifiers("9C020YCAC61234", "180b68a0-22f3-4411-f248-585dd92cd1dd")
    assert ms == "9C020YCAC6XXXX"; checks += 1
    assert mu == "180b68a0-XXXX-XXXX-XXXX-XXXXXXXXXXXX"; checks += 1

    b_bruce = decode_build_info_reply(struct.pack("<II", 337784, 3))
    assert b_bruce == {"build_number": 337784, "board_rev": 3, "firmware_family": "bruce"}; checks += 1
    b_gotham = decode_build_info_reply(struct.pack("<II", 282115, 2))
    assert b_gotham == {"build_number": 282115, "board_rev": 2, "firmware_family": "gotham"}; checks += 1

    assert decode_battery_reply(struct.pack("<H", 87)) == 87; checks += 1
    assert decode_cstr(b"GA00722-US\x00\x00") == "GA00722-US"; checks += 1

    p_str = decode_provisioning_reply(b"ReadyForEndUserUse")
    assert p_str == {"state_name": "ReadyForEndUserUse", "state_code": 5}; checks += 1
    p_code = decode_provisioning_reply(struct.pack("<I", 3))
    assert p_code == {"state_name": "ReadyForDeveloperUse", "state_code": 3}; checks += 1

    u_locked = decode_unlock_reply(struct.pack("<II", 1, 0))
    assert u_locked["vendor_usb_task_active"] is True and u_locked["unlocked"] is False; checks += 1
    u_open = decode_unlock_reply(struct.pack("<II", 1, 0xFFFFFFFF))
    assert u_open["unlocked"] is True; checks += 1

    print(f"SELFTEST OK ({checks} checks)")


def print_report(info):
    print(f"Stadia Controller ({info['usb_id']}, vendor interface {info['interface']})")
    print(f"  USB Serial       : {info['serial'] or '<unavailable>'} ({info['hardware_stage']})")
    print(f"  SsdpUdn (0x87)   : {info['ssdp_udn']}")
    print(f"  SKU / ModelId    : {info['sku']!r} / {info['model_id']!r} (0x88 / 0x89)")
    print(f"  Firmware         : {info['firmware_family']} build {info['build_number']} (board_rev={info['board_rev']})")
    print(f"  Provisioning     : {info['provisioning_state']} (code={info['provisioning_code']})")
    polled_note = "polled via 0x83" if info["battery_polled"] else "cached (pass --poll-battery to refresh)"
    print(f"  Battery SoC      : {info['battery_soc_percent']}% ({polled_note})")
    print(
        f"  VendorUsbTask    : active={info['vendor_usb_task_active']} "
        f"unlock_level={info['unlock_level']} (unlocked={info['unlocked']})"
    )


def main():
    ap = argparse.ArgumentParser(description="Read-only USB EP0 diagnostics for Google Stadia Controller.")
    ap.add_argument("--poll-battery", action="store_true", help="Issue bRequest 0x83 and wait 500 ms before reading 0x84")
    ap.add_argument("--redact", action="store_true", help="Mask serial suffix and SsdpUdn UUID for public logs")
    ap.add_argument("--json", action="store_true", help="Emit JSON output")
    ap.add_argument("--selftest", action="store_true", help="Run offline unit tests without hardware")
    args = ap.parse_args()

    if args.selftest:
        run_selftest()
        return 0

    try:
        info = query_controller(poll_battery=args.poll_battery, redact=args.redact)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print_report(info)
    return 0


if __name__ == "__main__":
    sys.exit(main())
