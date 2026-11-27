# `stadia-ram-hello` — Bare-Metal DTCM Firmware (Switch Pro Controller over Classic BT HID)

Minimal freestanding Cortex-M7 firmware for the Google Stadia Controller (`MIMXRT1061` + `BCM43458F`) loaded temporarily into DTCM (`0x20000000`, entry `0x20000400`) via `tchebb/nxp-sdp-overrun` (`ROMC` session mode, no fuse/flash writes).

## Features
- **Classic Bluetooth HID (`057E:2009` Nintendo Switch Pro Controller):** `BCM43458F` CTS strap + `.hcd` `patchram`, paginated SDP (`MaxAttributeByteCount` + 2-byte `ContinuationState`), SSP + encryption, RAM `Link Key` cache (4 slots, same-session instant reconnect), L2CAP HID Control/Interrupt (`PSM 0x0011`/`0x0013`), SPI stick calibration (`0x603D`) and deadzone parameters (`0x6086`/`0x6098`), HCI ACL reassembly (`PB = 01b`).
- **Full Inputs:** 17 digital buttons, `LX/LY` & `RX/RY` analog sticks (`ADC1_IN9..12`), and `L2`/`R2` Hall-effect triggers (`ADC1_IN13`/`IN8`, enabled via active-LOW `GPIO2_10 = 0` with hysteresis).
- **Hardware Haptics (`FlexPWM4` + `XBARA1`):** Decodes Switch HD rumble (`A2 10` / `A2 01`, `subcmd 0x48`) and drives both ERM motors at ~30 kHz (`PWM4` SM2/SM3 Ch A on `GPIO_B1_14`/`15` + active-LOW enables `GPIO2_16`/`17`) with a ~1.5 s safety watchdog.
- **Real Battery & Power Shortcuts:** Wakes `BQ2742X` (`0x55`) via `GPIO2_28` and polls `BQ2742X` + `BQ25601` (`0x6B`) for real Switch Pro HID battery/charging reporting (`pkt[3]`); hold **`Assistant` (~1 s)** to disconnect & re-pair, or **`Stadia + Assistant` (~2.5 s)** for clean `PMIC_KILL` hardware power-off (`GPIO4_03 = 0`, `GPIO4_02 = 1`).
- **USB CDC-ACM Live Console:** Non-blocking TX ring buffer + RX diagnostic commands (`b` battery, `i` 5/5 I2C scan, `p` PWM4 regs, `m <L> <R>` manual rumble) on `USB1` (`0x402E0000`) using OCRAM (`0x20200000`) for DMA descriptors/buffers.

## Build & Boot

1. Extract the Broadcom `.hcd` patchram header from your own local `slot_a_bruce.bin` dump (not redistributed in this repo):
   ```bash
   python3 ../../tools/extract_hcd.py /path/to/slot_a_bruce.bin -o bcm43458f_hcd.h
   ```
2. Compile with `arm-none-eabi-gcc`:
   ```bash
   make clean all
   ```
3. Hold **`Options + Assistant + A + Y`** while plugging in USB-C (NXP BootROM SDP `1fc9:0135`), then boot in one command:
   ```bash
   python3 ../../tools/boot_dtcm.py --bin build/stadia_hello.bin --console
   ```
   See [docs/bare-metal-bringup.md](../../docs/bare-metal-bringup.md) for details.
