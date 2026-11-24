# `stadia-ram-hello` — Bare-Metal DTCM Firmware (Switch Pro Controller over Classic BT HID)

Minimal freestanding Cortex-M7 firmware for the Google Stadia Controller (`MIMXRT1061` + `BCM43458F`) loaded temporarily into DTCM (`0x20000000`, entry `0x20000400`) via `tchebb/nxp-sdp-overrun` (`ROMC` session mode, no fuse/flash writes).

## Features
- **Classic Bluetooth HID (`057E:2009` Nintendo Switch Pro Controller):** `BCM43458F` CTS strap + `.hcd` `patchram`, paginated SDP (`MaxAttributeByteCount` + 2-byte `ContinuationState`), SSP + encryption, L2CAP HID Control/Interrupt (`PSM 0x0011`/`0x0013`), SPI stick calibration (`0x603D`) and deadzone parameters (`0x6086`/`0x6098`), HCI ACL reassembly (`PB = 01b`).
- **Full Inputs:** 17 digital buttons, `LX/LY` & `RX/RY` analog sticks (`ADC1_IN9..12`), and `L2`/`R2` Hall-effect triggers (`ADC1_IN13`/`IN8`, enabled via active-LOW `GPIO2_10 = 0` with hysteresis).
- **USB CDC-ACM Live Console:** Non-blocking TX ring buffer + RX command interface on `USB1` (`0x402E0000`) using OCRAM (`0x20200000`) for DMA descriptors/buffers.

## Build

1. Extract the Broadcom `.hcd` patchram header from your own local `slot_a_bruce.bin` dump (not redistributed in this repo):
   ```bash
   python3 ../../tools/extract_hcd.py /path/to/slot_a_bruce.bin -o bcm43458f_hcd.h
   ```
2. Compile with `arm-none-eabi-gcc`:
   ```bash
   make clean all
   ```
3. Load `build/stadia_hello.bin` to `0x20000000` and jump to `0x20000400` after unlocking `ROMC` session mode (`hab=0x56787856`). See [docs/bare-metal-bringup.md](../../docs/bare-metal-bringup.md) for details.
