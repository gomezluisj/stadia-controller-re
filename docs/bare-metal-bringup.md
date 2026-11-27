# Bare-Metal Bring-Up Guide (DTCM / OCRAM)

[← Back to README](../README.md)

This document summarizes the hardware-verified bring-up sequence for running custom bare-metal ARM Cortex-M7 firmware on a stock Google Stadia Controller (`MIMXRT1061`, PVT) without modifying fuses or NOR flash.

---

## 1. Execution Path (`ROMC` Session Mode)

1. Put the controller in NXP BootROM SDP mode (`1fc9:0135`).
2. Run [`tchebb/nxp-sdp-overrun`](https://github.com/tchebb/nxp-sdp-overrun) to unlock HAB for the current boot session (`REPORT_STATUS` returns `hab=0x56787856`).
3. Upload an unsigned IVT image (`csf = 0`, entry in DTCM `0x20000400`) via `SDP WRITE_FILE (0x0404)` to `0x20000000` and execute via `SDP JUMP_ADDRESS (0x0b0b)` to `0x20000400`.
4. Note: `SDP READ_REGISTER` remains masked in `ROMC` session mode (`0x89232389` / `4323ccdc7eba4de9`); for NOR preservation dumps or `OCOTP` reads, load a standard `MIMXRT1062` `ivt_flashloader.bin` (`15a2:0073`, `blhost`).

---

## 2. Live Debug Console (USB CDC-ACM on `USB1`)

- **Critical i.MX RT1060 DMA constraint:** `USB1` (`0x402E0000`) DMA **cannot access DTCM (`0x20000000`)**. Place `dQH`, `dTD`, and endpoint TX/RX buffers in **OCRAM (`0x20200000`)**.
- Use a **non-blocking TX ring buffer** drained from the main USB poll loop (with ZLP handling on exact 64-byte chunks) so an idle host port (`DTR=1` without a reader) cannot stall the main loop or overflow `LPUART3` RX during Bluetooth traffic.

---

## 3. Inputs, LEDs & I2C Peripherals

- **Ring LED (`TI LP5562` @ `LPI2C2` `0x30`, `GPIO_B0_04/05` `ALT2`):**
  - `0x0E` (`W_PWM`) = White, `0x03` (`G_PWM`) = Orange/Amber, `0x04` (`R_PWM`) = Red, `0x02` (`B_PWM`) = unwired.
- **17 Digital Buttons:** Active-low with pull-ups on `GPIO1..4` (see full table in [docs/hardware-pinout.md](hardware-pinout.md)).
- **Analog Thumbsticks (`ADC1` `0x400C4000`, `GPIO_AD_B1_04..07` `ALT5`, `pad=0`):**
  - `RX` = `ADC1_IN9`, `RY` = `ADC1_IN10`, `LX` = `ADC1_IN11`, `LY` = `ADC1_IN12` (idle `~2000–2150`).
- **Hall-Effect Triggers (`L2`/`R2`, `ADC1_IN13` / `ADC1_IN8`):**
  - **Power enable:** drive **`GPIO2_10` (`GPIO_B0_10`, `0x401F8164 = ALT5`) LOW (`DR = 0`, `GDIR = 1`)**. If left high-Z or driven HIGH, both channels float around `~330` and discharge under sampling.
  - Measured 12-bit ranges with `GPIO2_10 = 0`:
    - `R2` (`ADC1_IN8`, `GPIO_AD_B1_03`): idle `~1747`, full press `~616`.
    - `L2` (`ADC1_IN13`, `GPIO_AD_B1_08`): idle `~1734`, full press `~578`.
- **`LPI2C1` (`0x403F0000`, `GPIO_AD_B1_00/01` `ALT3`):**
  - `0x1A` (`WM8904` codec), `0x3B` (`TS3A227E` 3.5 mm jack switch, `reg 0x00 = 0x11`, regs `0x00..0x1C`), `0x55` (`BQ2742X` fuel gauge, requires `GPOUT` toggle to wake), `0x6B` (`BQ25601` charger).

---

## 4. Classic Bluetooth HID (`BCM43458F` on `LPUART3`)

1. **Power-on CTS strap:** Mux `GPIO_EMC_15` (`0x401F8050`) to `ALT5` (`GPIO4_15`) and hold **LOW** while pulsing `BT_REG_ON` (`GPIO3_20`, `GPIO_EMC_34`) low→high (~50 ms each), then switch `GPIO_EMC_15` back to `ALT2` (`LPUART3_CTS_B`).
2. **`LPUART3` (`0x4018C000`, `115200` baud):** Enable `RXRTSE` (`MODIR` bit 3) and TX/RX FIFOs (`FIFO` `+0x28`).
3. **Patchram upload:** Send `HCI_Reset (0x0C03)`, `Download_Minidriver (0xFC2E)`, then the 228 `.hcd` packets extracted from `slot_a_bruce.bin` (`0x6012f5d0..0x6013c69a`, `53,450 B`).
4. **SDP pagination (critical for macOS):** macOS sends `SDP_ServiceAttributeRequest` with `MaxAttributeByteCount = 0x0100` (256 B). HID records exceeding 256 B **must** be paginated using a 2-byte `ContinuationState`, otherwise macOS silently drops L2CAP SDP and disconnects ACL 15 s later (`0x13`).
5. **Switch Pro Controller (`057E:2009`) SPI calibration & stick parameters (critical for macOS `GCController` & Switch 2):**
   - Factory stick calibration (`0x603D..0x604E`): pack both X and Y ranges as `0x540` (`1344`, `{ 0x40, 0x05, 0x54 }`) around `0x800` center (`{ 0x00, 0x08, 0x80 }`) so Stadia sticks reach full `±1.00`.
   - Factory stick parameters (`0x6086..0x6097` Left, `0x6098..0x60A9` Right): do **not** return `0xFF × 18` — bytes `3..5` encode the deadzone (`0xFFF = 4095`), which causes hosts to clamp all 4 stick axes to `0.00`. Return the standard Pro Controller parameter block (`deadzone = 0x0AE = 174`), and handle combined/overlapping SPI reads byte-by-byte (Switch 2 reads `0x6080` len `0x18` spanning `0x6080..0x6097`, and `0x603D` len `0x19` spanning `0x603D..0x6055`).
6. **Nintendo Switch 2 pairing requirements (critical — skipping these causes instant `0x13` disconnect right after L2CAP open):**
   - Reply **`Auth_Requirements = 0x04` (General Bonding)** in `HCI_IO_Capability_Request_Reply` (not `0x02` Dedicated Bonding).
   - Enable Role Switch + Sniff Mode via `HCI_Write_Default_Link_Policy_Settings (0x080F)` = `0x0005` (Switch 2 immediately enters Sniff Mode `HCI EVT 0x14` after L2CAP `0x0011`/`0x0013` open).
   - Echo the incoming MTU option (`01 02 A0 02`) in `L2CAP_Configuration_Response (0x05)`.
   - Keep `0x3F` mode event-driven (no unsolicited `0x3F` flood right after `0x0013` opens); pressing `L + R` triggers Switch 2's full Pro Controller init sequence (`0x02`, `0x08`, `0x10`, `0x03 0x30`, `0x40`, `0x30`, `0x48`).
7. **Verified end-to-end on macOS & Nintendo Switch 2:**
   - **macOS (`GameController.framework`):** enumerates natively as `Switch Pro Controller` (`extendedGamepad = true`); all buttons (`A/B/X/Y`, `L1/R1`, `L2/ZL` & `R2/ZR` with zero-chatter hysteresis, `L3/R3`, `Plus/Minus`, 4-way `D-Pad`) and all 4 analog axes (`LX/LY`, `RX/RY` reaching `[-1.00..+1.00]`) verified live.
   - **Nintendo Switch 2:** pairs via *Controllers → Change Grip/Order* (`L + R`), completes full Pro Controller init, and all buttons, triggers (`L2`/`R2`), and sticks work live.
