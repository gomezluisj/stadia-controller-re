# Hardware Inventory, Pinout & BLE Profile

[← Back to README](../README.md)

## 1. Hardware inventory (verified)

| Component | Detail |
|---|---|
| SoC | NXP **i.MX RT106x** (Cortex-M7 600 MHz "crossover" MCU). `USB_ANALOG_DIGPROG` (`0x400D8260`) reads `0x006C0000` (`0x6C` = RT106x family rev `A0` — verified live via `15a2:0073`; the register does not distinguish RT1061/1062/1064, while PCB silkscreen in public teardowns, lidskialf.net, identifies `MIMXRT1061`) |
| Serial flash | 16 MB QSPI NOR (`XIP`-mapped at `0x60000000`, SPI via FlexSPI). Google's WebUSB/WebHID flasher (`zatanna`) accepts two JEDEC variants: **GigaDevice `GD25Q128`/`GD25LQ128` (`0x17C8`, `"Giga-16m"`)** and **Winbond `W25Q128JW` (`0x17EF`, `"Winbond-16m"`)**. Hardware-verified on this PVT unit: JEDEC `0x17C8` (`"Giga-16m"`), `FCB` v1.4.0 (`0x56010400`, `page=256`, `sector=4096`, `nonzero_lut_words=13`, `sha256=3de91732ab0118a97b68f853e764359a0ea85489bfaf8b6ba8501a9ec8467c31`) |
| Bluetooth radio | Broadcom **BCM43458F** (BT 4.2 + BLE; plus 802.11ac SDIO WLAN under `gotham`). Patchram string: `;BCM43458F 37.4MHz Google Gotham BT4.2 [Version: 0054.0161]`. Host loads it via HCI patchram at boot |
| Crypto anchor | HAB (High-Assurance Boot) in mask ROM, RSA-4096/SHA-256; SRK hash fused in OCOTP (`2928f879 e93b4d4f 8670e5c1 afb77878 8a91174f c155995f 51e0bea9 50ff002a`, `CFG5 = 0x04d0c01e` live-verified via `15a2:0073`); **i.MX RT106x BEE Region 1 (`AES-128-ECB`)** protects `0x60006000–0x6003ffff` |
| Ring LED / I2C | **TI LP5562** RGBW LED driver (`led_driver_lp5562.cc`), hardware-verified on **`LPI2C2` (`0x403F4000`)** via **`GPIO_B0_04` (SCL, `ALT2`) / `GPIO_B0_05` (SDA, `ALT2`)** (`SELECT_INPUT` `0x401F84D4/D8 = 1`; bare-metal blink confirmed over I2C `0x30..0x33` without altering fuses). Board pinmux also configures **`LPI2C1` (`0x403F0000`)** on `GPIO_AD_B1_00/01` (`ALT3`) |
| USB IDs | App mode `18d1:9400` (`Google`), 2nd-stage Bootloader `18d1:946b` (`Google Inc. / Bootloader`, `bcdDevice=0x0001`), BootROM SDP `1fc9:0135`, Google flashloader `15a2:0073` |
| BLE identity | Name `StadiaFXXXX-XXXX` (suffix = last 2 bytes of MAC), pure LE (`Flags 0x06` — BR/EDR not supported). Advertising window ≈ 2 min after pairing mode (orange LED blink), then sleeps — re-enter with 4+ s Stadia-button hold |

Serial example referenced throughout: `9C020YCAC6XXXX` (production build; serial masked in this public copy). Per `zatanna`, Google's flasher classifies serial prefixes as `91..94` = unsupported early EVT/proto units, `95..97` or `9800..9808` = `DVT` (`bruce_dvt_a_dev_signed.bin`), and `9809+` / `99+` / `9C+` = `PVT` (`bruce_pvt_a_prod_signed.bin`).

### Peripheral & input pinout (verified from `Board::Board()` @ `0x600717a0..0x600748ec` & pinmux table @ `0x60102920`)

Static disassembly of `gotham 337784` Slot A (`Board::Board()` @ `0x600717a0..0x600748ec`, `0x60076698..0x600768bc`, and ITCM `0x00002528` loaded from `0x60042d44..0x60042e32`) resolves the hardware input, I2C, radio, audio, and haptic buses on the i.MX RT106x PCB:

- **Analog sticks & triggers (`ADC1` @ `0x400C4000`, `0x60072f96..0x60073000` & `0x60074510..0x60074558`):**

| Input | ADC Channel | RT106x Pad | `board` offset (`0x200064c0`) | Consumer object |
|---|---|---|---|---|
| **Right Trigger (`R2`)** | `ADC1_IN8` (logical `7`) | `GPIO_AD_B1_03` | `board + 0xb74` | `right_trigger` (`board + 0x6910`; Hall LUT `0x60102800`: `0x058b..0x0320`; **hardware-verified** with active-LOW `GPIO2_10 = 0`: idle `~1747`, full press `~616`) |
| **Right Joystick X (`RX`)** | `ADC1_IN9` (logical `8`) | `GPIO_AD_B1_04` | `board + 0xbec` | `right_joystick + 0x54` (`board + 0x67a0`; **hardware-verified**) |
| **Right Joystick Y (`RY`)** | `ADC1_IN10` (logical `9`) | `GPIO_AD_B1_05` | `board + 0xc28` | `right_joystick + 0x58` (`board + 0x67a0`; **hardware-verified**) |
| **Left Joystick X (`LX`)** | `ADC1_IN11` (logical `10`) | `GPIO_AD_B1_06` | `board + 0xc64` | `left_joystick + 0x54` (`board + 0x67fc`; **hardware-verified**) |
| **Left Joystick Y (`LY`)** | `ADC1_IN12` (logical `11`) | `GPIO_AD_B1_07` | `board + 0xca0` | `left_joystick + 0x58` (`board + 0x67fc`; **hardware-verified**) |
| **Left Trigger (`L2`)** | `ADC1_IN13` (logical `12`) | `GPIO_AD_B1_08` | `board + 0xb38` | `left_trigger` (`board + 0x6858`; Hall LUT `0x60102800`: `0x058b..0x0320`; **hardware-verified** with active-LOW `GPIO2_10 = 0`: idle `~1734`, full press `~578`) |

*(Both Hall-effect triggers are powered via **active-LOW `GPIO2_10` (`GPIO_B0_10`, `0x401F8164 = ALT5`, `DR = 0`, `GDIR = 1`)**; when `GPIO2_10` is left high-Z or driven HIGH, `IN8`/`IN13` float around `~330` and discharge under sampling. Internal telemetry ADC channels also sit at `board + 0xbb0` on `ADC1` and `board + 0xd34` on `ADC2_IN15`.)*

- **17 Button & D-Pad GPIOs (`0x60102920` entries `idx = 0..16`, `board + 0x284 + idx * 0x3c`, registered at `0x60076698..0x600768bc` into `state[+0x210..+0x222]` and `[0x20002fc8 + 8..26]`, packed into the 3-byte button bitfield by ITCM `0x00002528` / `0x60042d44..0x60042e32`):**

| `idx` | RT106x Pad | GPIO | `board` offset | Getter | `state` offset | Bitfield (`0x60042db6`) | Role (`0x60070744..0x60070a56` HID parsers) |
|---:|---|---|---|---|---|---|---|
| `0` | `GPIO_SD_B1_00` | `GPIO3_00` | `+0x284` | `0x60084b1c` | `+0x214` | `byte0` bit 6 | **`D-Pad Up`** (`[r4+12]`) |
| `1` | `GPIO_SD_B1_01` | `GPIO3_01` | `+0x2c0` | `0x60084b24` | `+0x215` | `byte0` bit 7 | **`D-Pad Down`** (`[r4+13]`) |
| `2` | `GPIO_SD_B1_02` | `GPIO3_02` | `+0x2fc` | `0x60084b2c` | `+0x216` | `byte0` bit 4 | **`D-Pad Left`** (`[r4+14]`) |
| `3` | `GPIO_SD_B1_03` | `GPIO3_03` | `+0x338` | `0x60084b34` | `+0x217` | `byte0` bit 5 | **`D-Pad Right`** (`[r4+15]`) |
| `4` | `GPIO_B0_00` | `GPIO2_00` | `+0x374` | `0x60084acc` | `+0x210` | `byte0` bit 0 | **`A`** (`[r4+8]`) |
| `5` | `GPIO_B0_01` | `GPIO2_01` | `+0x3b0` | `0x60084afc` | `+0x211` | `byte0` bit 1 | **`B`** (`[r4+9]`) |
| `6` | `GPIO_B0_02` | `GPIO2_02` | `+0x3ec` | `0x60084ad4` | `+0x212` | `byte0` bit 2 | **`X`** (`[r4+10]`) |
| `7` | `GPIO_B0_03` | `GPIO2_03` | `+0x428` | `0x60084adc` | `+0x213` | `byte0` bit 3 | **`Y`** (`[r4+11]`) |
| `8` | `GPIO_B0_11` | `GPIO2_11` | `+0x464` | `0x60084af4` | `+0x222` | `byte1` bit 4 | **`Stadia`** (Home, `[r4+26]`) |
| `9` | `GPIO_B0_12` | `GPIO2_12` | `+0x4a0` | `0x60084ae4` | `+0x21e` | `byte1` bit 3 | **`Options`** (`…`, `[r4+22]`) |
| `10` | `GPIO_B0_13` | `GPIO2_13` | `+0x4dc` | `0x60084b14` | `+0x21f` | `byte1` bit 2 | **`Menu`** (`≡`, `[r4+23]`) |
| `11` | `GPIO_B0_14` | `GPIO2_14` | `+0x518` | `0x60084aec` | `+0x220` | `byte1` bit 1 | **`Assistant`** (`[r4+24]`) |
| `12` | `GPIO_B0_15` | `GPIO2_15` | `+0x554` | `0x60084b3c` | `+0x221` | `byte1` bit 0 | **`Capture`** (`[r4+25]`) |
| `13` | `GPIO_AD_B0_00` | `GPIO1_00` | `+0x590` | `0x60084b44` | `+0x21c` | `byte1` bit 7 | **`L3`** (left stick click, `[r4+20]`; **hardware-verified**) |
| `14` | `GPIO_AD_B0_02` | `GPIO1_02` | `+0x5cc` | `0x60084b4c` | `+0x21d` | `byte2` bit 0 | **`R3`** (right stick click, `[r4+21]`; `L2`/`R2` digital thresholds in `byte2` bits 1–2) |
| `15` | `GPIO_EMC_00` | `GPIO4_00` | `+0x608` | `0x60084b04` | `+0x218` | `byte1` bit 5 | **`L1`** (`[r4+16]`; **hardware-verified**) |
| `16` | `GPIO_EMC_01` | `GPIO4_01` | `+0x644` | `0x60084b0c` | `+0x219` | `byte1` bit 6 | **`R1`** (`[r4+17]`; **hardware-verified**) |

*(Exact 1:1 mapping cross-checked across all three Tandem HID parsers in `slot_a_bruce.bin`: DS3 Report `0x01` @ `0x60070744`, DS4 Report `0x01` @ `0x60070834`, and Stadia Report `0x03` @ `0x60070948`, all targeting canonical struct `0x20002fc8` `[+8..+26]`, and **all 17 digital buttons confirmed on live hardware**.)*

- **Broadcom `BCM43458F` Bluetooth HCI (`BLE_EN` @ `0x6006a390`, `BrcmPatchramStart` @ `0x60098820`):**
  - **`BT_REG_ON` (`BLE_EN`):** `GPIO_EMC_34` (`GPIO3_20`, `idx = 55`, `board + 0x1738`; optional 2nd pin `GPIO_EMC_41` / `GPIO3_27` at `board + 0x1814`).
  - **Power-on CTS strap sequence (`0x6006bf20` → `0x6006ec50` / `0x6006ec90`):** Before asserting `BT_REG_ON` (`GPIO3_20`), firmware muxes `GPIO_EMC_15` (`0x401F8050`) to `ALT5` (`GPIO4_15`) and drives it **LOW** during the 50 ms `BT_REG_ON` low/high reset pulse, then switches `GPIO_EMC_15` back to `ALT2` (`LPUART3_CTS_B`, `0x401F8534=0`).
  - **`LPUART3` (`0x4018C000`, initial baud `115200` @ `0x6007302e`):** `GPIO_EMC_13` (`TX`, `0x401F8048=2`, `SELECT_INPUT 0x401F853C=1`), `GPIO_EMC_14` (`RX`, `0x401F804C=2`, `SELECT_INPUT 0x401F8538=1`), `GPIO_EMC_15` (`CTS_B`, `0x401F8050=2`, `SELECT_INPUT 0x401F8534=0`), `GPIO_EMC_16` (`RTS_B`, `0x401F8054=2`). Hardware flow control uses `LPUART3_MODIR` (`+0x24`, bit 3 `RXRTSE`) with TX/RX FIFOs enabled (`LPUART3_FIFO` `+0x28`).
  - **Embedded `.hcd` `patchram` blob:** `0x6012f5d0..0x6013c69a` (`53,450 B`, `228` vendor commands: `0xfc2e` `Download_Minidriver` + `228` HCD packets `0xfc4c` `Write_RAM` .. `0xfc4e` `Launch_RAM`).

- **I2C, SDIO, Audio & PWM buses (`0x60102d10..0x60102fa0`, `0x6007401a..0x600740d4`, `0x6007455c..0x60074580`):**
  - **`LPI2C2` (`0x403F4000`, `GPIO_B0_04/05` `ALT2`, `board + 0xfa8`):** TI **LP5562** ring LED at `0x30` (`board + 0x4304`, `[LP5562+0] = NULL` — no external `EN` GPIO). **Hardware-verified channel wiring:** `W_PWM` (`0x0E`) = **White**, `G_PWM` (`0x03`) = **Orange / Amber**, `R_PWM` (`0x04`) = **Red**, `B_PWM` (`0x02`) = **unwired / no LED die** (writing only `B` turns the LED off).
  - **`LPI2C1` (`0x403F0000`, `GPIO_AD_B1_00/01` `ALT3`, `board + 0xf80`):** I2C peripherals at `0x6b` (`board + 0x4364`, TI **`BQ25601`** battery charger), `0x1a` (`board + 0x432c`, **`WM8904`** audio codec; **hardware-verified**), `0x3b` (`board + 0x433c`, TI **`TS3A227E`** 3.5 mm headset jack detect switch, `reg 0x00 = 0x11`, regs `0x00..0x1C`; **hardware-verified**), and `0x55` (`board + 0x4348`, TI **`BQ2742X`** fuel gauge, requires `GPOUT` toggle to exit shutdown).
  - **`USDHC1` (`GPIO_SD_B0_00..05` `ALT0`):** `BCM43458F` SDIO WLAN.
  - **`SAI1` (`GPIO_AD_B1_09, 13, 14, 15` `ALT3`):** Headset audio I2S/MCLK.
  - **Haptic / rumble motors (`0x6007455c..0x60074580`):** `GPIO_B1_00` (`GPIO2_16`, `idx = 25`, `board + 0x800`) and `GPIO_B1_01` (`GPIO2_17`, `idx = 26`, `board + 0x82c`) paired with `PWM1..4` (`0x403DC000..0x403E8000`) objects at `board + 0x1488` and `board + 0x1544`.

---

## 6. BLE profile (measured, end-to-end)

Instrumentation: Linux BlueZ + `btmon` raw captures, against `F4:2F:0C:XX:XX:XX` (MAC masked in this public copy) with fresh bond.

Services — **100% SIG-standard UUIDs, zero Google-proprietary GATT**:

- `1800` GAP, `1801` GATT (Service Changed `2a05`), `180a` Device Information, `180f` Battery (`2a19`)
- `1812` HID over GATT (HOGP):
  - Report Map `2a4b` (182 bytes) — Usage Page Generic Desktop, **Usage Gamepad (`09 05`)**
  - Input Report `2a4d` Report ID `0x03` (read+notify)
  - Output Report `2a4d` Report ID `0x05` (LEDs/rumble)
  - Protocol Mode `2a4e`, Control Point `2a4c`

Report Map content: 15 buttons (`95 0f` — A B X Y, L1 R1 L3 R3, menu, capture, Google Assistant, Stadia, L2 R2), hat switch (8-way), 2 sticks (X/Y + Z/Rz), analog triggers via `09 c5` (Brake/RL2) and `09 c4` (Accelerator/RR2), Consumer page volume/play-pause, and battery-strength display output. This is a **clean HID gamepad descriptor** with no vendor-proprietary gamepad quirks.

**Pairing gotchas (the #1 source of "my Stadia won't connect" on Linux):**
1. Requires a **fresh bond** — stale bonds cause ATT `0x05`/`0x08` (Insufficient Authentication / Authorization; observed as `Operation Not Authorized` over D-Bus) on writes and non-subscribable CCCDs. (Separately, reads of the Output Report returned ATT `0x0a`, Attribute Not Found.) Delete and re-pair.
2. Requires a **registered pairing agent** in the connecting process (`bluetoothctl default-agent`, `NoInputNoOutput`); silent failures log as `"No agent available for request type 2"` in bluetoothd.
3. Connection must be initiated **inside the advertising window** — re-enter pairing mode if it slept.

**With bruce, input flows:** verified end-to-end on Linux — the unit enumerates as `/dev/input/js0` (`StadiaFXXXX-XXXX`), sticks/buttons/triggers produce continuous events over 60+ reads in 20 s. *Earlier claims of "no input reports" were an artifact of testing under gotham (the Wi-Fi-era fallback), not bruce.* If you inherited an unresponsive unit, check which image is actually running in slot A.

---
