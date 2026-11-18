# Stadia Controller — Technical Architecture & Firmware Reference

**Complete reverse-engineering reference for the Google Stadia Controller**
*Compiled November 2026 from static and live analysis of the device (BootROM SDP probing → bootloader → application firmware). Public, partially artifact-backed, with explicit open items documented below. Shared so future researchers don't have to re-derive any of this.*

> **Scope & ethics note.** This document describes defensive architecture and analysis methodology only. No exploit code, no private keys, no vendor-confidential material (everything below was recovered from public firmware images and standard RE tooling). The device is a discontinued product; research like this is how its 16 MB of NOR stays useful after its cloud service went dark in January 2023 and Google's official flasher page followed it.
>
> **TL;DR for the impatient:** the Stadia Controller is an NXP i.MX RT106x (measured MIMXRT1061, Cortex-M7 crossover) + Broadcom BCM43458F BLE radio, with a strongly locked Google firmware stack (bootloader enforces RSA-4096 slot verification against a fused SRK hash, and the audited parsers in "bruce", the 2023 Bluetooth-mode image, use nanopb-with-bounds, strnlen-bounded RPC, and descriptor-checked protobuf). Across the statically audited Google corpus (317 restricted flashloader, 547 bootloader, 4,690 application "bruce" functions discovered by Ghidra), we found no memory-corruption bug in bootloader KVS/slots, USB vendor RPC, BLE GATT Prepare/Execute Write, or NVRAM protobuf. In the **NXP BootROM** (`imxrt1060.bootrom.bin`, `a5d9af17…e58f8e`), our static audit closed OCOTP fuse-write primitives and DCD/CSF `WRITE_DATA` peripheral validation (§4, issue #3), leaving the ROM's internal parsers and USB HID transport outside coverage; subsequently, `tchebb/nxp-sdp-overrun` (§10) demonstrated a 3-byte global buffer overrun in the BootROM's SDP USB HID callback (`sdp_hid_callback` @ `0x0020ea7e`, `HAB 4.3.7`), enabling unsigned code execution in SDP via `ROMC` session patching (per-boot) or `FIELD_RETURN` configuration. Elsewhere: bounded OUT/IN behavior in the EP0 path (`issue #1`, §7.4) was verified on hardware (`0x21` OUT and `0xC1` IN on `18d1:9400`, plus 64-byte ITCM `0x00000000` readback via `0xA1` on `18d1:946b`, all volatile in RAM); and surgical NOR captures (§1, §9 item 5) resolved the `Boot IVT` (`self = 0x60001000`, `entry = 0x60801000`), `Slot B` (`gotham 235551`), and **i.MX RT106x BEE Region 1 (`AES-128-ECB`, `g = 16`)** encryption across `0x006000–0x03ffff`.
>
> The BootROM was characterized through live SDP/HAB experiments and targeted static disassembly of its OCOTP and CSF Write-Data paths (§3, §4). The previously open BLE path (ATT Signed Write, 0xD2/CSRK) was closed statically across all three firmware images — CMAC-8 signature verification exists in each (§7.2) — and the gotham audit (§7.4) covered its BLE/ATT, key-store, and NOR persistence layers. Once Bluetooth-mode firmware is loaded, the unit works as a standard generic BLE gamepad on Linux/macOS/Windows/Android.

---

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
| **Right Trigger (`R2`)** | `ADC1_IN7` | `GPIO_AD_B1_02` | `board + 0xb74` | `right_trigger` (`board + 0x6910`) |
| **Left Joystick X (`LX`)** | `ADC1_IN8` | `GPIO_AD_B1_03` | `board + 0xbec` | `left_joystick + 0x54` (`board + 0x67fc`) |
| **Left Joystick Y (`LY`)** | `ADC1_IN9` | `GPIO_AD_B1_04` | `board + 0xc28` | `left_joystick + 0x58` (`board + 0x67fc`) |
| **Right Joystick X (`RX`)** | `ADC1_IN10` | `GPIO_AD_B1_05` | `board + 0xc64` | `right_joystick + 0x54` (`board + 0x67a0`) |
| **Right Joystick Y (`RY`)** | `ADC1_IN11` | `GPIO_AD_B1_06` | `board + 0xca0` | `right_joystick + 0x58` (`board + 0x67a0`) |
| **Left Trigger (`L2`)** | `ADC1_IN12` | `GPIO_AD_B1_07` | `board + 0xb38` | `left_trigger` (`board + 0x6858`) |

*(Internal telemetry ADC channels also sit at `board + 0xbb0` on `ADC1` and `board + 0xd34` on `ADC2_IN15`.)*

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

*(Exact 1:1 mapping cross-checked across all three Tandem HID parsers in `slot_a_bruce.bin`: DS3 Report `0x01` @ `0x60070744`, DS4 Report `0x01` @ `0x60070834`, and Stadia Report `0x03` @ `0x60070948`, all targeting canonical struct `0x20002fc8` `[+8..+26]`, and confirmed on live hardware via `L1`, `R1`, and `L3`.)*

- **Broadcom `BCM43458F` Bluetooth HCI (`BLE_EN` @ `0x6006a390`, `BrcmPatchramStart` @ `0x60098820`):**
  - **`BT_REG_ON` (`BLE_EN`):** `GPIO_EMC_34` (`GPIO3_20`, `idx = 55`, `board + 0x1738`; optional 2nd pin `GPIO_EMC_41` / `GPIO3_27` at `board + 0x1814`).
  - **`LPUART3` (`0x4018C000`, initial baud `115200` @ `0x6007302e`):** `GPIO_EMC_13` (`TX`, `0x401F8048=2`, `SELECT_INPUT 0x401F853C=1`), `GPIO_EMC_14` (`RX`, `0x401F804C=2`, `SELECT_INPUT 0x401F8538=1`), `GPIO_EMC_15` (`CTS_B`, `0x401F8050=2`, `SELECT_INPUT 0x401F8534=0`), `GPIO_EMC_16` (`RTS_B`, `0x401F8054=2`).
  - **Embedded `.hcd` `patchram` blob:** `0x6012f5d0..0x6013c69a` (`53,450 B`, `228` vendor commands: `0xfc2e` `Download_Minidriver` + `228` HCD packets `0xfc4c` `Write_RAM` .. `0xfc4e` `Launch_RAM`).

- **I2C, SDIO, Audio & PWM buses (`0x60102d10..0x60102fa0`, `0x6007401a..0x600740d4`, `0x6007455c..0x60074580`):**
  - **`LPI2C2` (`0x403F4000`, `GPIO_B0_04/05` `ALT2`, `board + 0xfa8`):** TI **LP5562** ring LED at `0x30` (`board + 0x4304`, `[LP5562+0] = NULL` — no external `EN` GPIO). **Hardware-verified channel wiring:** `W_PWM` (`0x0E`) = **White**, `G_PWM` (`0x03`) = **Orange / Amber**, `R_PWM` (`0x04`) = **Red**, `B_PWM` (`0x02`) = **unwired / no LED die** (writing only `B` turns the LED off).
  - **`LPI2C1` (`0x403F0000`, `GPIO_AD_B1_00/01` `ALT3`, `board + 0xf80`):** I2C peripherals at `0x6b` (`board + 0x431c`, charger/PMIC), `0x1a` (`board + 0x432c`, audio codec), `0x3b` (`board + 0x433c`, auxiliary device), and `0x55` (`board + 0x4348`, fuel gauge).
  - **`USDHC1` (`GPIO_SD_B0_00..05` `ALT0`):** `BCM43458F` SDIO WLAN.
  - **`SAI1` (`GPIO_AD_B1_09, 13, 14, 15` `ALT3`):** Headset audio I2S/MCLK.
  - **Haptic / rumble motors (`0x6007455c..0x60074580`):** `GPIO_B1_00` (`GPIO2_16`, `idx = 25`, `board + 0x800`) and `GPIO_B1_01` (`GPIO2_17`, `idx = 26`, `board + 0x82c`) paired with `PWM1..4` (`0x403DC000..0x403E8000`) objects at `board + 0x1488` and `board + 0x1544`.

### Firmware layout in NOR (16 MB; physical offset vs XIP address — offsets for stadiatool/flash tools, XIP for Ghidra/execution)

Static disassembly of the firmware's board partition constructor (`board + 0x4378`, `13` descriptors registered via `0x600717a0` in `bruce 337784` at `0x600740e2..0x60074580`, identical in `gotham 316382` at file offset `0x6f764..0x6fade` / XIP `0x608af764..0x608afade`) resolves all **4,096 × 4 KiB sectors (`16 MiB`)** with zero unmapped bytes:

| Sectors (4K) | Region / Role | Physical NOR offset | XIP address | Size | ID (`+0x08`) | KVS flags / Verified firmware & hardware behavior |
|---|---|---|---|---:|---|---|
| `0x000..0x000` | **FCB** | `0x000000–0x000fff` | `0x60000000–0x60000fff` | 4 KiB | *(raw)* | FlexSPI Configuration Block (`"FCFB"`, v1.4.0 `0x56010400`, LUT at `+0x080`, `512 B` used) |
| `0x001..0x001` | **Boot IVT** | `0x001000–0x001fff` | `0x60001000–0x60001fff` | 4 KiB | `0x12` (`18`) | Initial IVT + `boot_data` read by Mask ROM (`board+0x4384`, `entry=0x60801000`, `self=0x60001000`) |
| `0x002..0x003` | **Crash Store B** | `0x002000–0x003fff` | `0x60002000–0x60003fff` | 8 KiB | `0x07` (`7`) | Secondary crash/bug report store (`board+0x6740`, below `0x60006000`; `0xFF` erased in hardware capture) |
| `0x004..0x005` | **Reserved Low** | `0x004000–0x005fff` | `0x60004000–0x60005fff` | 8 KiB | `0x0a` (`10`) | Protected low partition (`board+0x4460`, below write window; `0xFF` erased in hardware capture) |
| `0x006..0x027` | **Bug Reports** | `0x006000–0x027fff` | `0x60006000–0x60027fff` | 136 KiB | `0x08` (`8`) | Primary crash/bug-report store (`bug_report.cc`; BEE Region 1 encrypted on NOR; readable decrypted pre-unlock via Bulk `kind=3, op=9`) |
| `0x028..0x02f` | **User KVS** | `0x028000–0x02ffff` | `0x60028000–0x6002ffff` | 32 KiB | `0x09` (`9`) | Runtime/User KVS (`kvs=(1,0)`, `board+0x4510`; BEE Region 1 `AES-128-ECB`, `g=16`; erased on `FactoryReset` `0x600749ea`) |
| `0x030..0x033` | **BT NVRAM** | `0x030000–0x033fff` | `0x60030000–0x60033fff` | 16 KiB | `0x0b` (`11`) | Bluetooth bond / device database (`0x60065454`; BEE Region 1 `AES-128-ECB`; erased on `FactoryReset` `0x60074a66`) |
| `0x034..0x037` | **Aux Data 17** | `0x034000–0x037fff` | `0x60034000–0x60037fff` | 16 KiB | `0x11` (`17`) | Auxiliary data partition (`board+0x6700`; BEE Region 1 `AES-128-ECB`) |
| `0x038..0x03b` | **Factory KVS** | `0x038000–0x03bfff` | `0x60038000–0x6003bfff` | 16 KiB | `0x05` (`5`) | Persistent Factory KVS (`kvs=(1,1)`, `board+0x5060`; BEE Region 1 `AES-128-ECB`, `g=16`; survives `FactoryReset`: serial, calibration, `IsDfDevice`, `SsdpUdn`) |
| `0x03c..0x03f` | **Bootloader KVS** | `0x03c000–0x03ffff` | `0x6003c000–0x6003ffff` | 16 KiB | `0x04` (`4`) | Bootloader metadata KVS (`kvs=(1,1)`, `board+0x5bb0`; BEE Region 1 `AES-128-ECB`, `g=16`: `AppAMeta`, `AppBMeta`, `RecoveryMeta`, `BookkeepVer`, `BookkeepMeta`) |
| `0x040..0x7ff` | **Application A** | `0x040000–0x7fffff` | `0x60040000–0x607fffff` | 7.75 MiB | `0x01` (`1`) | Active slot A (`bruce` `1,050,984 B` or `gotham` OTA `4,163,944 B`) |
| `0x800..0x81f` | **Bootloader A** | `0x800000–0x81ffff` | `0x60800000–0x6081ffff` | 128 KiB | `0x03` (`3`) | Google second-stage bootloader A (`zatanna` id `3`; starts with `0x1000`-byte IVT header identical to `0x001000` before `0x60801000`) |
| `0x820..0x83f` | **Bootloader B** | `0x820000–0x83ffff` | `0x60820000–0x6083ffff` | 128 KiB | `0x13` (`19`) | Redundant second-stage bootloader B (`zatanna` id `4`; `0xFF` erased in captured PVT hardware header sample) |
| `0x840..0xfff` | **Application B** | `0x840000–0xffffff` | `0x60840000–0x60ffffff` | 7.75 MiB | `0x02` (`2`) | Hosts factory `gotham` build `235551` (`0x840000–0xc20030` authenticated span verified on hardware; upper tail erased `0xFF`) |

**Partition-extent reconciliation, hardware BEE encryption & slot header contract (resolved against `zatanna`, `bruce 337784`, `gotham` 235551/282115/316382, and captured NOR dumps; see §9 item 5):**

- **All KVS/NVRAM/crash partitions sit inside the first 256 KiB (`0x000000–0x03ffff`) and `0x006000–0x03ffff` uses i.MX RT106x BEE Region 1 (`AES-128-ECB`):** earlier partial-dump notes guessed that KVS/NVRAM lived past `0xc38968` in `Application B` and labeled `0x609b2dec..0x60B169A8+` a `"NOR-resident shared code library"` (which was simply the upper ~3 MiB of the monolithic `gotham` Slot B binary truncated at 1 MiB). Cross-checking `0x600717d4` → `0x60067e44` → `0x6005f07c` confirms that firmware configures **i.MX RT106x BEE Region 1 (`0x403EC000`, `AES-128-ECB`)** and DCP (`0x6005f310` @ `0x402FC000`) across base **`0x60006000` with length `0x3a000` (`0x006000–0x03ffff`, sectors `0x006..0x03f`)**, enforcing **16-byte alignment (`g = 16`)** on every write (`0x6005f320..0x6005f326`), while `FactoryReset` (`0x600749d0`) erases only `id=9` (`user_kvs`) and `id=11` (`bt_nvram`). Because BEE decrypts AHB reads in silicon while FlexSPI IPCMD (`0x402A8100`) reads raw NOR pins, a surgical `low_256k.bin` capture shows plaintext `FCB`/`Boot IVT` in `0x000000–0x001fff`, erased `0xFF` in `0x002000–0x005fff`, and 16-byte AES ciphertext blocks in `0x006000–0x03ffff` (inspected structurally with `tools/nor_slice_inspect.py` / `tools/kvs_parse.py`).
- **`BuildInfo` metadata block (`slot_base + 0x400`, `256 B`):** every application image carries a fixed 256-byte descriptor at `+0x400` (`0x60040400` / `0x60840400`) validated by both the flasher and `firmware_image_upload.cc`: header magic `0x747315a2` at `+0x00`, version `1` at `+0x04`, size `0x100` at `+0x08`, type `2` at `+0x0c`, flash size `0x01000000` (`16 MiB`) at `+0x10`, `uint32_le` build number at `+0x14` (`337784` in `bruce`, `235551` in factory `Slot B`, `282115` / `316382` in `gotham` OTAs), and footer magic `0x4786cd88` at `+0xfc`.
- **Trailing HABv4 IVT pointer (`*(slot_base + 0x1c)`):** Cortex-M7 vector table word 7 (`+0x1c`) stores the XIP address of the slot's trailing HABv4 IVT (`0x6013f000` in `bruce`, `0x60c20000` in factory `Slot B 235551`, `0x60437000` in `gotham-pvt-a`, `0x60c37000` in `gotham-pvt-b`), explaining why bootloader `FUN_6080200c` dereferences `slot_base + 0x1c`. Each trailing `boot_data` declares `length = 0x007c0000`, while `AUTHENTICATE_DATA` covers `base_vma .. csf_ptr` (`0x0ff030 B` in `bruce`, `0x3e0030 B` in `Slot B 235551`, `0x3f7030 B` in `gotham 282115/316382`; inspectable offline with `tools/ivt_csf_inspect.py`).
- **`SRC_GPR5/6/7` reset handoff (`0x400F8030..0x400F8038`):** `zatanna` clears `SRC_GPR5..7`, writes `1` (Slot A) or `2` (Slot B) to `SRC_GPR7` (`0x400F8038`), and resets the chip to steer the bootloader to the newly flashed slot; `Reset_Handler` checks/clears `SRC_GPR6` (`0x400F8034`) for fast/warm-reset handling.

---

## 2. Boot chain

```
Mask ROM (HAB4.1)                                  — NXP code, non-updatable
  → reads the fixed IVT at 0x60001000 (flash offset 0x1000, verified on hardware dump, sha256 1403ac0c…697423):
    header    0x412000D1  (d1 00 20 41)
    entry     0x60801000  ← bootloader reset/vector entry past the 0x1000-byte IVT block at 0x800000
    dcd       0x00000000
    boot_data 0x60001020  (start 0x60000000, length 0x01000000 = whole 16 MB XIP space)
    self      0x60001000  ← verified in NOR: matches standard NXP HABv4 contract (closes 0x60001020 doc discrepancy)
    csf       0x60818000  (the bootloader's own CSF inside Bootloader A at 0x800000)
  → verifies bootloader IVT+CSF @ 0x60800000 (Bootloader A begins with an identical copy of 0x001000..0x001fff before code at 0x60801000)
Google bootloader (128 KB @ flash offset 0x800000) — 547 functions decompiled
  → checks slot SHA-256 vs KVS metadata (AppAMeta/AppBMeta/RecoveryMeta) when KVS entries exist
  → invokes ROM HAB to verify slot IVT+CSF (key IMG3_1_usr)
  → jumps to active slot image (Slot A bruce @ 0x60040000, or fallback Slot B factory gotham 235551 @ 0x60840000)
bruce / gotham (application)                        — 4,690 functions decompiled
  → loads BCM43458F patchram, bring-up board/USB/BLE, runs stack + game logic
```

**Recovery & bootloader USB modes (works on any unit):**
- Holding **`...` (Menu)** alone while plugging USB enumerates the **Google 2nd-stage Bootloader (`18d1:946b`, `Google Inc. / Bootloader`, `bcdDevice=0x0001`, serial `'serial-not-set'`)**.
- From `18d1:946b`, pressing **`...` + `Assistant` + `A` + `Y`** simultaneously transitions immediately to **BootROM SDP (`1fc9:0135`)** (matching the 2-step sequence in `app_combined.js`, alongside holding Stadia ~10 s while plugging USB), accepting `WRITE_FILE` to load a flashloader over HID. Every hardware capture below used this non-destructive recovery path.

---

## 3. ROM HAB / SDP surface (what USB can and cannot do)

Measured raw, below any parser layer:

| SDP command | Result on this unit |
|---|---|
| `WRITE_FILE` (0x0404) | succeeds (`0x88888888`) — the only real write primitive |
| `READ_REGISTER` (0x0101) | returns **synthetic constants** per region in HAB-closed state (OCRAM/ROM → `0x89232389`; others → `0x33223300`, `0xcb83cc9c`). Round-trip write→read confirms the gate — there is **no real memory-read path via SDP** |
| `JUMP_ADDRESS` / DCD | only accepts HAB-signed images. Behavioral note for HAB-closed units: a raw unsigned JUMP to RAM (no valid IVT header — a bare `WFI` test in DTCM) is rejected by the SDP command's **syntactic pre-check**, HAB is never invoked, and the SDP session stays alive. A JUMP to the official NXP flashloader carries a well-formed IVT+CSF (`0x402000D1`), so it *does* reach `hab_rvt.authenticate_image()`, fails the SRK compare against Google's fuses, and the resulting HAB security failure terminates USB enumeration — which is why that test made the chip vanish from the bus |
| `REPORT_STATUS` | `0x12343412` = `HAB_MODE_CLOSED` (open is `0x56787856`) |

HAB status was captured raw at the HID-report level (immune to tool-parser bugs), which matters: two tools in this project initially reported "verified" values that turned out to be parser artifacts. **Verify primitives with raw captures before building conclusions on them** — this saved us twice.

### Google's restricted flashloader (`restricted_ivt_flashloader.bin`, VID `15a2:0073`)

Google replaced NXP's general-purpose flashloader with a stripped one:

- **Whitelisted** memory access: USB PHY ID register (`0x400D8260`) and the **FlexSPI register window `0x402A8000+`**. That FlexSPI window is the load-bearing hole: it allows driving the SPI engine directly, which is how slot/bootloader NOR dumps and scratch-page erase/write primitives were demonstrated (a genuine KVS-partition dump has not yet been captured/parsed; see `docs/kvs-parser-spec.md` §2/§5).
- **Whitelist-rejected** (`0x27d8`): writes to RAM, OCOTP shadow, OCRAM, DTCM/ITCM, XIP space, ROM.
- **Compiled out** (`0x2710` = disabled): `FlashReadResource`, `Call`, `Execute`.
- OCOTP (fuses) is not readable over USB via the restricted flashloader (`0x27d8` whitelist rejection) or SDP `READ_REGISTER` — SRK hash extraction via USB is dead on its own (on-chip executing firmware such as `bootloader` and `bruce` reads OCOTP registers directly via `0x401F4000`; see §4 and §7.1.1).

With FlexSPI register access, characterized primitives (REV 4.1, all verified against a reference dump with scratch-page canaries):

- **LUT injection:** `configure_memory(9, 0x2000)` copies the FCB lookup table into `FlexSPI->LUT` (sequence: LUTKEY `0x5AF05AF0` → UNLOCK → copy). Living A/B proof: patching 2 bytes of the read sequence changes returned data.
- **Arbitrary NOR read** via IPCMD — caveat: 1 word per transaction (`IDATSZ=4`); the multi-word burst repeats word 0 because the RFDR FIFO doesn't advance on pop.
- **4-byte AHB write** to a virgin page, and **sector erase 4K/64K** — the working incantation is: set `IPCR1[19:16] ISEQID` (not IPCMD!) with `ISEQNUM=0` — the field counts *additional* sequences, so 0 executes exactly 1 — and `IDATSZ=0` for no-data opcodes; then WREN seq 3 → RDSR seq 1 (expect `WEL=0x02`) → SE4K seq 5 / BE64K seq 8 / PP seq 9. LUT indices 0-based: READ=0, RDSR=1, WREN=3, SE4K=5, BE64K=8, PP=9 (matches NXP SDK).

Full repro tooling: GaryOderNichts's `stadiatool` (§10) (`dump_final.py` with resumable dump + canary + auto-recovery `dev.reset()`, `flashloader.py`, `sdp.py`).

### 3.5 `Reset_Handler` FlexRAM configuration & runtime scatter-load map

Early static disassembly often flagged direct Thumb calls to `0x0000xxxx` (such as `FUN_00001084` OCOTP fuse read and `FUN_00000fac` `DCACHE_CleanByRange`) as ambiguous between mask ROM and RAM. In the application images (`bruce` and `gotham`), `Reset_Handler` at `slot_base + 0x500` (`0x60040500` / `0x60840500`) calls `FUN_6006f634` (`bruce`) to configure i.MX RT106x FlexRAM via `IOMUXC_GPR` before scatter-loading:

- `IOMUXC_GPR_GPR14` (`0x400AC038`): sets `[23:16] = 0xA8`.
- `IOMUXC_GPR_GPR17` (`0x400AC044`): writes `0xFFAAAAAA`, partitioning all 16 FlexRAM banks as **12 × 32 KiB DTCM (`384 KiB`, `0x20000000–0x2005ffff`)** and **4 × 32 KiB ITCM (`128 KiB`, `0x00000000–0x0001ffff`)**, then enables ITCM/DTCM via `IOMUXC_GPR_GPR16` (`0x400AC040`). *(In `restricted_ivt_flashloader.bin`, which executes from OCRAM `0x20000000+` before FlexRAM remapping, `0x00001835` remains in NXP BootROM space; in `bruce`/`gotham`, `0x00000000+` is application ITCM `.ramfunc`.)*

Following `SystemInit`, `Reset_Handler` executes a 15-word scatter-load table at `slot_base + 0x5f4..0x62c` (reproducible in Ghidra via `ghidra/MapScatterLoad.java`):

| Section | `bruce` (`337784`, Slot A) | `gotham-pvt-a` (`282115`, Slot A) | `gotham-pvt-b` (`316382`, Slot B) | Factory `gotham` (`235551`, Slot B HW dump) |
|---|---|---|---|---|
| **ITCM `.ramfunc`** (copy from Flash LMA `+0x81c`) | `0x00000000–0x0000bdf8` (`48,632 B`, LMA `0x6004081c`) | `0x00000000–0x0001e128` (`123,176 B`, LMA `0x6004081c`) | `0x00000000–0x0001e128` (`123,176 B`, LMA `0x6084081c`) | `0x00000000–0x00026088` (`155,784 B`, LMA `0x6084081c`) |
| **DTCM `.bss_low`** (zero-filled) | `0x20000000–0x20002740` (`10,048 B`) | `0x20000000–0x20002760` (`10,080 B`) | `0x20000000–0x20002760` (`10,080 B`) | `0x20000000–0x20002760` (`10,080 B`) |
| **DTCM `.data`** (copy from Flash LMA) | `0x20002740–0x20003fd8` (`6,296 B`, LMA `0x6013d5a8`) | `0x20002760–0x20006dfc` (`18,076 B`, LMA `0x60432778`) | `0x20002760–0x20006dfc` (`18,076 B`, LMA `0x60c32670`) | `0x20002760–0x20006cac` (`17,740 B`, LMA `0x60c1af68`) |
| **DTCM `.noinit`** (retained gap) | `0x20003fd8–0x20004020` (`72 B`) | `0x20006dfc–0x20007020` (`548 B`) | `0x20006dfc–0x20007020` (`548 B`) | `0x20006cac–0x20007020` (`884 B`) |
| **DTCM `.bss_high`** (zero-filled) | `0x20004020–0x2002a824` (`157,700 B`) | `0x20007020–0x2003e684` (`226,916 B`) | `0x20007020–0x2003e684` (`226,916 B`) | `0x20007020–0x2003e7b4` (`227,220 B`) |
| **DTCM `.stack`** (`MSP`, filled `0xaabbaabb`) | `0x2002a828–0x2002b828` (`4,096 B`) | `0x2003e688–0x2003f688` (`4,096 B`) | `0x2003e688–0x2003f688` (`4,096 B`) | `0x2003e7b8–0x2003f7b8` (`4,096 B`) |

*(Factory `gotham 235551` in Slot B enters `Reset_Handler` at `0x60840501` and branches to `entry_after_init = 0x608669f1`.)*

Consequently, in `bruce` (`337784`), `FUN_00000fac` (`DCACHE_CleanByRange` writing `SCB->DCCMVAC` at `0xE000EF68`) resides in Flash at `0x6004081c + 0xfac = 0x600417c8`, and `FUN_00001084` (`OCOTP_ReadFuseWord`) resides in Flash at `0x6004081c + 0x1084 = 0x600418a0`.

---

## 4. Signature & verification architecture

Key facts recovered from decompilation of the bootloader (decompilation corpus not hosted in this repo; addresses in exec space `0x60800000`):

- **App verifier** (`FUN_6080200c`): the app IVT must be exactly at `0x60040000` (region `0x60040000–0x6013ffff`); if `IVT+0x1c` points to a signature table it demands `HAB_SUCCESS = 0xF0` from the ROM using key **`IMG3_1_usr`**. The "unsigned path" only exists if the bootloader's own CSF pointer is 0 — in stock it's `0x60818000` ≠ 0 → dead.
- **Chip status check:** ROM call `0x200324` returns `0xCC`; cross-referencing the i.MX RT1060 RM §9.12.1 and u-boot `hab.h`, that's `REPORT_STATUS` reporting `hab_config` = **closed**, which makes the composite-CSF=0 rejection structural, not accidental.
- **Fingerprinting pre-boot** (`FUN_608027c8`): SHA-256 of each slot against KVS metadata (`AppAMeta/AppBMeta/RecoveryMeta`) using OpenSSL (GothamBIO). Mismatch → slot swap/fallback.
- **Key hierarchy:** SRK3_sha256_4096_65537_v3_ca root (hash in OCOTP fuses, *not* in flash — slot `0x8a0` of NOR is zeros), CSF3_1 / IMG3_1 usr certs, RSA-4096. **Dev- and stage-signed images use different SRKs with revoked indexes in runtime on production units** — physically verified: flashing a dev- or stage-signed image to slot A → rejected, clean fallback to slot B.
- Bootloader update path supports verified install + rollback; no skip-verification branch exists.
- **Bootloader-side ASN.1/PKCS#7 audit (2026-11-13): there is no ASN.1 parser in the bootloader.** The verification vtable entries (`DAT_60801fa0/0x60801fa4/0x60801fa8`) resolve to `0x00200304` (report status), `0x0020032c` (`authenticate_image`), and `0x00200308` (close) — the i.MX RT1060's ROM-resident `hab_rvt`. All certificate/SRK/signature DER parsing happens inside the NXP mask ROM; the bootloader's own contribution is (1) the IVT bounds-check `FUN_60801fac` (validates all 255 pointer entries against the image range before invoking HAB), (2) versioned fixed-size KVS metadata reads (`FUN_6080cbf4` — BookkeepVer requires exactly version 8 / size 0x20; BookkeepMeta reads 2 bytes behind a size check), (3) an in-place SHA-256 block transform (`FUN_6080ce00`) used for slot fingerprinting, and (4) the update path `FUN_60801dd4`, which authenticates **both** the incoming and the currently-installed bootloader IVT via the ROM before installing ("New bootloader failed image auth" aborts without touching flash). All bootloader-owned parsing surfaces verified sane.
- **Field-return / OCOTP fuse-blow & CSF `WRITE_DATA` audit (2026-11-15, issue #3):** Neither the **i.MX RT1060 mask BootROM** (`imxrt1060.bootrom.bin`, 128 KB, sha256 `a5d9af17…e58f8e`) nor the **Google second-stage bootloader** (`0x60800000`, 128 KB) contains an OCOTP fuse-write primitive. In the mask ROM, the mandatory write-unlock key `0x3E77` (`HW_OCOTP_CTRL[31:16]`) is absent image-wide (~49 shadow-register reads, 0 stores; `0x401F4000` appears only as a region-table datum at `0x0021B098`), and the HAB `UNLOCK` command (`0xB2`, `FUN_00203578` in the 20-entry command registry `FUN_00207f04`) only records a descriptor post-verify without touching MMIO. Furthermore, CSF `WRITE_DATA` (`0xCC`, `FUN_00206530`) validates every `(addr, value)` pair through the byte-accurate peripheral allowlist `FUN_0020726c` (table at `0x0021B0F4`: IOMUXC/CCM/FlexSPI windows, excluding both OCOTP `0x401F4000–0x401F7FFF` and ROM working RAM `0x20200000–0x20207FFF`), and the only allowlist bypass (the stage-4 authenticated-data marker) is written exclusively inside `AUTHENTICATE_DATA` (`0xCA`, `FUN_00206b90`) **after** the RSA signature check (`0x00206e04`, `cmp r0, #0xf0` at `0x00206e22`) succeeds — closing the classic i.MX pre-verdict DCD/CSF `WRITE_DATA` tampering class on this ROM (and the Boot IVT carries `dcd = 0x00000000`). In the Google bootloader, all 4 OCOTP references (`0x60807f84`, `0x6080abbc`, `0x6080b13c`) are `ldr.w` shadow reads (`+0x410/+0x420/+0x460`) plus the `"BEE key doesn't match fused value"` compare, and all provisioning-lifecycle strings (`ReadyForDeveloperUse`, `NeedsFdr`, `FailedToReadFuses`) exist only in the application firmware (`bruce`), downstream of the bootloader's `FUN_6080200c` signature gate.

**Consequence & BootROM USB HID scope note (updated 2026-11-17):** while Google's bootloader and application images enforce strict HABv4 verification and the NXP BootROM's own `UNLOCK`/`WRITE_DATA` command handlers contain no direct `OCOTP` store path, our BootROM audit intentionally excluded the ROM's **USB HID transport layer** prior to command parsing. Public research by `tchebb/nxp-sdp-overrun` (§10) subsequently identified a **3-byte global buffer overrun in `sdp_hid_callback()` (`0x0020ea7e` in `HAB 4.3.7`)**: it validates `reportLength <= 2048` for `sdp_hid_request` (`0x2020723c`) before setting `reportBuffer = sdp_hid_request + 3`, allowing up to 3 trailing bytes to overwrite the low bytes of the adjacent `sdp_dev` configuration pointer (`0x20207a3c`) before `OCOTP.SW_STICKY` locks `FIELD_RETURN`. This provides a USB-only SDP path for session-scoped unsigned execution (via `ROMC` patching) or permanent `FIELD_RETURN` transition, whereas unassisted cold-boot execution from NOR without SDP intervention still requires a HABv4-signed image unless `FIELD_RETURN` is set.

### 4.1 HABv4 CSF layout & `BCM43458F` co-processor coverage (verified offline)

All five reference signed images inspected with `tools/ivt_csf_inspect.py` share the **identical 4-key RSA-4096 SRK table** (`table_sha256 = 4f69081a259e648a...`, fused OCOTP `SRK_HASH = 79f828294f4d3be9c1e570867878b7af4f17918a5f9955c1a9bee0512a00ff50`), differing only in `INSTALL_SRK` key selection (`src_idx = 0` / `SRK1`, revoked in OCOTP `SRK_REVOKE` on PVT units, vs `src_idx = 2` / `SRK3`):

| Image | Base VMA | IVT (`+off`) | CSF (`+off`) | `SRK` idx | `AUTHENTICATE_DATA` span |
|---|---|---|---|---|---|
| `restricted_ivt_flashloader.bin` (`100,672 B`) | `0x20000000` | `0x20000400` (`+0x400`) | `0x20017000` (`+0x17000`, `80 B` cmd stream + `UNLOCK eng=0x21 feat=0x2`) | `2` (`SRK3`) | `[0x20000000..0x20017000)` (`0x17000 B`) |
| `bruce_dvt_a_dev_signed.bin` (`1,050,984 B`) | `0x60040000` | `0x6013f000` (`+0xff000`) | `0x6013f030` (`+0xff030`, `72 B` cmd stream) | `0` (`SRK1`) | `[0x60040000..0x6013f030)` (`0x0ff030 B`) |
| `bruce_pvt_a_prod_signed.bin` (`1,050,984 B`) | `0x60040000` | `0x6013f000` (`+0xff000`) | `0x6013f030` (`+0xff030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60040000..0x6013f030)` (`0x0ff030 B`) |
| `ota.282115...gotham-pvt-a.bin` (`4,163,944 B`) | `0x60040000` | `0x60437000` (`+0x3f7000`) | `0x60437030` (`+0x3f7030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60040000..0x60437030)` (`0x3f7030 B`) |
| `ota.316382...gotham-pvt-b.bin` (`4,163,944 B`) | `0x60840000` | `0x60c37000` (`+0x3f7000`) | `0x60c37030` (`+0x3f7030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60840000..0x60c37030)` (`0x3f7030 B`) |
| Factory `gotham 235551` (Slot B HW dump) | `0x60840000` | `0x60c20000` (`+0x3e0000`) | `0x60c20030` (`+0x3e0030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60840000..0x60c20030)` (`0x3e0030 B`) |

**Embedded `BCM43458F` Bluetooth/WLAN co-processor firmware sits 100% inside the signed CSF span:**

- **Bluetooth `.hcd` patchram (`brcm_prm_init`):** in `bruce`, `0x60098820` issues `HCI_VSC_Download_Minidriver` (`0xfc2e`) and streams **228 `.hcd` records (`53,450 B`: 227 × `0xfc4c` `Write_RAM` + 1 × `0xfc4e` `Launch_RAM`)** matching `;BCM43458F 37.4MHz Google Gotham BT4.2 [Version: 0054.0161]`. This identical `53,450 B` blob resides at `0x6012f5d0..0x6013c69a` in `bruce` (`in_csf=True`), `0x6039ab46..0x603a7c10` in `gotham-pvt-a` (`in_csf=True`), and `0x60b9aa3e..0x60ba7b08` in `gotham-pvt-b` (`in_csf=True`).
- **802.11ac SDIO WLAN (`gotham` only):** `gotham` additionally embeds the Broadcom `BCM43458` (`0x14e4:0x43ab`) NVRAM (`macaddr=00:90:4c:c5:12:38`, `manfid=0x2d0`, `prodid=0x06e8` at `0x603470e9` / `0x60b46fe1`) and SDIO WLAN firmware (`43458c5-roml/sdio-ag-...` at `0x6042e947` / `0x60c2e83f`), both strictly inside `AUTHENTICATE_DATA` (`0x60437030` / `0x60c37030`). Radio patchram replacement in NOR therefore breaks RSA-4096 slot verification.

### CVE applicability (checked, not assumed)

| CVE | Verdict on RT1060 |
|---|---|
| CVE-2022-45163 (SDP info leak) | **Applies in class** (corrected assessment): the project's initial test of `READ_REGISTER` returned synthetic constants and early logs closed this CVE on that basis; red-team review corrected it — the actual vector is a *timing side channel in `CHECK_DATA` within DCD* (NCC Group/Fox-IT), not `READ_REGISTER`. That PoC remains untested on this unit, and whether RT1060 BootROM enforces the DCD peripheral allowlist on `CHECK_DATA` (`OCOTP` accessibility) is unverified — in any case it is a read primitive, not code-exec. |
| CVE-2026-19736 (TRNG) | No — targets i.MX RT5xx/RT6xx TRNG driver |
| CVE-2021-31532 (ROM patch peripheral) | No — LPC55xx / RT500 / RT600 family |

Remaining doors are hardware-only: SWD/JTAG (likely fuse-fused on pvt, and debug-RAM-only anyway — no cold-boot persistence), voltage/clock glitching of HAB compare, BEE encrypted-region keys, or replacing the bootloader (needs Google's private key).

---

## 5. Application firmware — codenames and roles

Two stock images shipped; both are still on most units (slot A + slot B):

| Codename | Ver | Role |
|---|---|---|
| **gotham** | 235551 | Wi-Fi-era firmware: Wi-Fi provisioning, Assistant, audio pipeline ("Synapse APM"), fallback gamepad |
| **bruce** | 337784 | The 2023 "Bluetooth mode" image: disables Wi-Fi/jack, pure BLE HID-over-GATT gamepad |

Both are HAB-signed production images. On any unit that received Google's January 2023 Bluetooth-mode update, Slot A holds bruce while Slot B retains the era-Wi-Fi factory image; units "lost" Bluetooth mode only when Slot A was overwritten or invalidated during experiments (the bootloader then falls back to Slot B). Loading bruce is *not* custom firmware — it is the official Google image, and the community flasher (`luigimannoni.github.io/stadia-controller-flasher`, WebHID mirror of the dead stadia.google.com flow) delivers it. Aftermarket note: Bluetooth mode disables the 3.5 mm jack and Wi-Fi permanently (by design of the image, reversible by re-flashing gotham from your own dump).

A **protobuf-over-USB vendor channel** exists in bruce's *app* mode (post-boot, unauthenticated, verb-based) used for provisioning/state — audited in §7.

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

## 7. Security audit of the application firmware (audited paths & open questions)

Method: Ghidra 12.2 headless, `ARM:LE:32:v8T`, BinaryLoader at `0x60040000`; decompilation of Ghidra-discovered functions (~169k lines / 4,690 functions in `bruce`). Heuristic scan for stack arrays indexed by unbounded variables, then manual review of top candidates. **Coverage caveat:** the heuristic scanner script is not hosted in `ghidra/`, `DecompAll.java` only emits auto-discovered functions (hence the `§7.2` unanalyzed callbacks), and stack-array indexing misses heap, RTOS concurrency, and DMA/control-transfer length mismatches (`issue #1`).

### 7.1 USB vendor RPC (static audit)

Note: this section documents static analysis of the decompiled handler. On live hardware running bruce, the USB bulk vendor interface did not arm by default during runtime testing — until the arming precondition was identified and demonstrated (2026-11-13, issue #2): a preceding EP0 class control IN with `bRequest 0x8b` (`bmRequestType 0xA1`, `wValue 0x0100`, `wIndex 0`) notifies the vendor provider record and wakes the vendor task, after which bulk OUT transfers are accepted and protobuf requests are decoded and dispatched normally. The same dispatcher is also reachable directly through EP0 control transfers, which is the path covered by the addendum at the end of this section.

Dispatcher `FUN_60077362` — dispatches by **verb** (`param_2 = bRequest - 0x80`, for `bRequest 0x80..0x8c`), operating on the `484 B` `.data` structure `ctx` at `0x20003670`:

| Verb (`bRequest`) | Action | Buffer & declared bound |
|---|---|---|
| `0` (`0x80`) | Enqueues `ctx+0x000` work item 0 (`0x60077111`: `"Disabling charging from USB Vendor"`); `req.buffer` unset (`NULL`, len 0) | — (NULL-target ITCM DMA on OUT; §7.1 addendum) |
| `1` (`0x81`) | Returns `ctx+0x190` (`uint32_le build_number = 337784`, `uint32_le board_rev`) | fixed `8` bytes |
| `2` (`0x82`) | Enqueues `ctx+0x064` work item 1 (`0x600770ed`: `"Entering shipping mode from USB Vendor"`); `req.buffer` unset | — (NULL-target ITCM DMA on OUT; §7.1 addendum) |
| `3` (`0x83`) | Enqueues `ctx+0x12c` work item 3 (`0x600db01b` → `UpdateGauge` `0x600772f4`: I2C fuel-gauge reg `0x1c` read into `*(uint16_t *)(ctx+0x1d8)`); `req.buffer` unset | — (NULL-target ITCM DMA on OUT; §7.1 addendum) |
| `4` (`0x84`) | Returns `ctx+0x1d8` (`uint16_le` battery SoC `%` populated by `UpdateGauge` / `bRequest 0x83` — e.g. `zatanna` `Ej` waits `500 ms` after `0x83` before reading `0x84`) | fixed `2` bytes |
| `5` (`0x85`) | Enqueues `ctx+0x0c8` work item 2 (`0x600770d9`: reboot `"FROM_USB_VENDOR"`); `req.buffer` unset | — (NULL-target ITCM DMA on OUT; §7.1 addendum) |
| `6` (`0x86`) | **Shipping-mode entry** (factory flow, `req.buffer` unset): fetches the runtime power-manager handle (`DAT_6005bdb0` → OCRAM global `0x2000d218`) and issues a synchronous system-service call via the app's syscall jump table (ITCM thunk `0x6013d398` → `0x1835`) — matching `"Entering shipping mode from USB Vendor"`. It is a state transition into the vendor power manager for shipping/long-storage mode, **not** a reboot into SDP/flashloader | — |
| `7` (`0x87`) | Copies `0x2000d1d5` (`SsdpUdn` / 36-char device UUID) into `ctx+0x1a0`, then returns it | copy/measure `strnlen`-bounded at `0x25` (`<= 0x24` chars + NUL) |
| `8, 9` (`0x88, 0x89`) | Return pointers to `ctx+0x1c5` (KVS key `0x3f` `"SKU"`, e.g. `"GA00722-US"`, defaults `"NoSku"`/`"BadSku"`) / `ctx+0x1d1` (KVS key `0x3d` `"ModelId"`, e.g. `"US/999"`, defaults `"NA/000"`/`"XX/000"`) | `strnlen`-bounded (`0xc` / `7` bytes), reject `len ≥ max` |
| `0xa` (`0x8a`) | Enforces IN direction (`req.setup < 0`), then binary lookup in 6-entry table `{opcode u32, char* name}` @ `0x6010a0dc` keyed on `ctx+0x1dc` (`MissingProvisioningData`, `NeedsFdr`, `FailedToReadFuses`, `ReadyFor{Developer,InternalUser,End}Use`) | returns ASCII state string capped at `0x3f` (`63` chars) |
| `0xb` (`0x8b`) | Signals vendor provider record `0x2001EDA8` via `FUN_60077744` → `FUN_600926b8` to wake/arm the bulk vendor task (`req.buffer` unset) | — |
| `0xc` (`0x8c`) | Calls `FUN_60077720` (`VendorUsbTask != NULL`) and `FUN_60077730` (`*(VendorUsbTask + 0x113c)` = `unlock_level`), writing them to `ctx+0x198` | fixed `8` bytes |
| default | Logs `"Invalid vendor RPC request: "` (`req.buffer` unset) | — |

Every length check is `strnlen`-style (`FUN_600db002` is literally a bounded strlen) with explicit upper bound rejection. **No overflow.** Scope note: this is a **static audit** of the decompiled dispatcher; in the live unit the unauthenticated USB vendor endpoint is a factory/provisioning channel whose bulk interface does not arm by default in normal user operation (the arming precondition — an EP0 `0xA1 0x8b` class IN — was demonstrated on 2026-11-13, issue #2). Note for researchers: the dispatcher's "invalid opcode" log is a live oracle — unknown verbs produce identifiable log output, making fuzzing measurable (we just found nothing to fuzz into).  

**Addendum (2026-11, issue #1): the EP0 control path into this dispatcher is not covered by the audit above.** The USB setup handler (FUN_60054dc0) dispatches class and vendor control requests to the same dispatcher, then runs the OUT data stage with the host's wLength as the receive length, without comparing it to the length the dispatcher declared for the request. Consequences, confirmed statically on bruce and on gotham 235551 (twin handler at 0x60076e5c, byte-identical sequence): (a) an OUT transfer on a read-mapped bRequest (e.g. 0x81, declared length 8 at ctx+0x190) writes as many bytes as the host sends, across the adjacent context fields, and the serial field at ctx+0x1c5 sits 0x35 bytes into that range; (b) dispatcher cases that return success without setting a buffer (0x80, 0x82, 0x83, 0x85, 0x86) leave the request buffer NULL, so an OUT data stage receives at address 0. The per-case bounds in the table above describe the dispatcher's own copies and are unaffected; the bug is in the setup handler's data stage, which this audit had not covered. Hardware demonstration by the reporter (issue #1); maintainer verification is static, with reproduction PoCs written from the code paths but not yet run on a maintainer unit.

#### 7.1.1 Bulk vendor channel: message schema, command table, and the unlock gate (reconciled 2026-11-15, live-verified)

The bulk interface (USB `Interface 0`, `bInterfaceClass = 0xff`, `EP 0x87 IN` / `EP 0x07 OUT`, `512 B` maxPacket; armed via `EP0 IN bRequest 0x8b`, which flips `0x8c` from `(0, 0)` to `(1, 0)`) is served by `vendor_usb_task` (`0x60077bec`, streaming nanopb decoder `0x60077850` reading up to `256 B` per callback `0x600db0e6`). Inspecting the `25 B`-per-entry nanopb `pb_field_t` descriptor `Request` at `0x60126e00` shows: **outer field 1 (`tag 0x08`) = `request_id`** (`u32` echoed in `Response.field_1`), followed by **fields `2..10` in a top-level `oneof`** (`which_payload` at `+0x08`, payload union starting at `+0x10`):

| `Request` oneof field | nanopb type (`+0x04`) | Role & live wire encoding |
|---|---|---|
| `field 2` | `0x37` (`MESSAGE`, `0x60127265`, `528 B`) | **Unlock token submission** (`bytes` token field 1 + `u32` field 2) — see gate below |
| `field 3` | `0x30` (`ONEOF \| VARINT`, `1 B` at `+0x10`) | **RPC op enum** — sent directly as `08 <id> 18 <op>` (`op 1 = unlock-challenge`, `op 2 = reboot`, `op 8 = event`, `op 9 = transfer_bug_report`, `op 10 = clear_bug_report`); `ops 1, 2, 8, 9, 10` pass `required_mask = 0` (`FUN_60077a48` / `FUN_60077948`); remaining ops (`3..7`) and `fields 4..10` dispatch through the 16-entry provider table at `0x6010a174` |

Complete 16-entry `VendorUsbTask` provider table (`0x6010a174` in `bruce`; each entry returns `1` = handled without re-check or `2` = requires `FUN_60077948` mask `0x3e8`):

| Index | Handler | Matches `(kind, op)` | Role & pre-unlock status |
|---|---|---|---|
| `0` | `0x60078340` | `kind=6` | `firmware_image_upload.cc` / `http_flash_writer.h` (partition-checked OTA flash writer) |
| `1` | `0x60078fec` | `kind=10` | Runtime/hardware telemetry → `resp.which=12` |
| `2` | `0x60078d88` | `kind=7` | Echo / ping → `resp.which=11` |
| `3` | `0x60078efc` | `kind=4` | Power state control (`"Unknown power state: "`) |
| `4` | `0x60078da8` | `kind=8` | `kvs_operations.cc`: KVS get by key name/type |
| `5` | `0x600db2be` | `kind=3, op=3` | Internal state-machine event (`resp.which=7`) |
| `6` | `0x600db408` | `kind=3, op=6` | Hardware I/O / indicator test (`resp.which=12`) |
| `7` | `0x60078ae0` | `kind=3, op=4` | `get_device_data.cc`: firmware build number & KVS SKU/device metadata |
| `8` | `0x60078be0` | `kind=3, op=5` | Power/gauge status getter |
| `9` | `0x600db56a` | `kind=3, op=7` | `BuildInfo` / slot metadata (`resp.which=13`) |
| `10` | `0x60079374` | `kind=3, op=2` | Reboot `"FROM_USB_BULK_VENDOR"` (**allowed pre-unlock** in `0x60077c58`) |
| `11` | `0x600db642` | `kind=3, op=8` | Post state-machine event (**allowed pre-unlock** in `0x60077c50`) |
| `12` | `0x6007946c` | `kind=3, op=9` | `transfer_bug_report.cc`: crash tombstone readout (**allowed pre-unlock**) |
| `13` | `0x600794a8` | `kind=3, op=10` | `clear_bug_report.cc`: erase crash tombstones (**allowed pre-unlock**) |
| `14` | `0x60079270` | `kind=5` | `stream_logs_update.cc`: register USB log streaming callback |
| `15` | `0x60078e00` | `kind=9` | `kvs_operations.cc`: KVS set/erase by key name/type |

A request with inner kind 1 is **not handled** (logged and dropped — the "unlock challenge request" is RPC kind 3/op 1, not a separate kind; an earlier revision of this section mislabeled it). Unknown kinds produce a generic error-3 response; a simple request (no nested message) logs `"Ignoring simple request that is not an 'unlock challenge'"`.

**The unlock gate — dual-path (reconciled 2026-11-15 via static disassembly and live `18d1:9400` probing).** `FUN_60077948(task, resp_msg, required_mask=r2, timeout_ms=r3)` sends a protobuf response (`timeout_ms = 0x3e8 = 1000 ms` in `r3`) after testing `bics.w r3, required_mask, [VendorUsbTask + 0x113c]` (`0x60077966`). For pre-unlock operations (`op 1` UnlockChallenge, `op 2` Reboot, `op 8` Event, `op 9` `transfer_bug_report`, `op 10` `clear_bug_report`), callers pass **`required_mask = 0` (`r2 = 0` at `0x60077a96` and `0x60077c66`)**; gated provider entries (`fields 4..10` and `RPC ops 3..7`) require `VendorUsbTask->unlock_level` (`+0x113c` in the `0x17c0 B` object at `*(0x2001ee0c)`) to be non-zero (initialized to **`0`** by `0x600776ae`, set to **`0xFFFFFFFF`** only by successful `field 2` unlock at `0x60077eaa`; `bRequest 0x8c` returns `(VendorUsbTask != NULL, *(VendorUsbTask + 0x113c))`). *(Historical note: an earlier draft cited `0x600c5c21` as an allow-mask at `ctx+0x113c`; `0x600c5c21` is an entry at `0x60118bcc` inside Broadcom Bluedroid's `bta_dm_action` table.)* `field 2` (token submission) has **two verification paths, selected by `FUN_600d7cdc`** (disasm `0x60077d92`):

- **Echo / serial-token path (factory/provisioning-gated):** the gate passes if **either** an **on-chip OCOTP silicon fuse** is set (`FUN_600d9934` → `FUN_60071348(0x26)` → ITCM `FUN_00001084(0x401F4000, 0x26, &out, 4)` — reading `HW_OCOTP_READ_FUSE_DATA` for fuse `0x26` bit 8) **or** the unit is factory-provisioned (`FUN_600d72ec(0x16,…)` = `IsDfDevice`, read-only in `bruce` with zero writers). Gate pass (`key_index = 3`) accepts a plain **echo compare** against the 36-char `SsdpUdn` UUID at `0x2000d1d5` (`strlen` + `memcmp` at `0x6013d168`) → **`unlock_level = 0xFFFFFFFF`**.
- **ECDSA path (retail units):** if both legs are clear (`ReadyForEndUserUse`), `field 2` falls through to `0x60077db2`, hashes `0x2000d1d5` (`SsdpUdn` UUID), `0x2000d168` (`DevSerial`), and the formatted challenge nonce from `ctx+0x135c` (`SHA256`), selects one of two **NIST P-256 (`prime256v1`) PEM public keys** (`0x60124756` / `0x60124808`) via OCOTP fuse field `6` (`(val & 0xC00000) == 0xC00000`, `key_index = 2` prod or `1` non-prod), and verifies via BoringSSL ECDSA (`0x60084e8c`).

**Live hardware verification (2026-11-15 on `ReadyForEndUserUse` PVT unit, `bruce 337784`):**
- Sending `08 01 18 01` (`Request.id=1`, `field 3 = 1`) after `EP0 0x8b` **responds immediately pre-unlock** (`60 B` `UnlockChallengeResponse`: `field 1` = 36-char `SsdpUdn` UUID, `field 2` = 14-char `DevSerial`, `field 3` = `key_index = 2`). *(An earlier `bulk_unlock_echo2.py` timeout had encoded `op 1` inside `field 2` instead of `oneof` varint `field 3`, and misread `r3 = 0x3e8` `1000 ms` USB timeout as a mask.)* Retail units are therefore stopped at **`field 2` ECDSA verification** unless signed by Google's NIST P-256 private key — and even if unlocked, `firmware_image_upload` remains constrained by BootROM/bootloader HAB RSA-4096 on cold boot.
- Sending `08 02 18 09` (`Request.id=2`, `field 3 = 9` `transfer_bug_report`) streams stored JSON bug reports from NOR partition `id=8` (`Response.field_14`, chunked in `<= 256 B` USB Bulk IN writes via `0x600775e0` / `0x600db02c`), including live `BootloaderKvsMetadata` (`BookkeepVer`, `BookkeepMeta` active/backup slot, `AppAMeta`/`AppBMeta` SHA-256 fingerprints and verification state) and `CarawayBuildInfo` (`commit_hash`, `version`, `build_date`), returning `{"error": "No bug report data available"}` when no pending report remains.

### 7.2 BLE GATT write paths (closed statically — Prepare/Execute and Signed Write)

- Prepare Write `FUN_60069160`: reassembly buffer at `ctx+0x1ac0` (0x259 bytes), check `offset + len < 0x259` with both operands `uint` and `len` bounded by MTU — **correct**.
- Execute Write `FUN_60069b20` → `FUN_6006ad00`: the Prepare-Write **value_offset is never persisted** (only handle @0x1abc and accumulated length @0x1abe) — the classic two-phase offset-overflow trap is dead by design.
- ~~Residual: attribute write callbacks via vtable `+0x10` receive up to 0x259 bytes; per-attribute destination buffers were not exhaustively audited.~~ **Closed (2026-11-13): sane.** The full write chain was re-derived from the binary (the handlers live outside the original decompilation corpus): ATT PDU entry `FUN_600f6516` validates `PDU length < negotiated MTU` before dispatch; MTU exchange (`FUN_600ae7f8`) clamps to 0x205; the direct-write path (`FUN_600aeb14`, stack buffer 600 B) cannot exceed max PDU payload 514 B; the central validator `FUN_600ad228` enforces properties/encryption/CCC-length before any callback. Per-attribute callbacks, disassembled from the GATT table in rodata (`0x6010b200`): Control Point/Protocol Mode writes clamp to exactly 1 byte (`FUN_600d4414`); Report `2a4d` writes are bound-checked against the report's registered size (`FUN_600df3a8`); read-only attributes are no-ops (`FUN_600d4368/436c`); the CCCD handler stores a u16 and tail-calls the notify; the reassembled-write slot `+0x10` (`FUN_600d4386`) is a pure trampoline whose only HID sink (`FUN_60058aa8`) was already audited (§7.1 addendum / issue #1: len 1–255, report ID 5, copies exactly 4 bytes). No unbounded copy exists at any level.

- **ATT Signed Write (opcode 0xD2 with CSRK) — closed statically across all three images (November 2026).** The server-side write-command handler performs full signature verification before accepting any write, in every image:

| Image | Router → extractor → verifier | Verification |
|---|---|---|
| bruce 337784 | `FUN_600ad9d8` → `FUN_600f41d0` → `FUN_600f0e98` | bond lookup, CSRK flag `+0x7b & 4`, anti-replay counter, CMAC-8 over the bond key, 8-byte memcmp |
| gotham OTA 282115 | `FUN_602e6312` → `FUN_602e2fda` (bond lookup `FUN_601dc474`, CMAC `FUN_601fcf4c`) | same checks |
| gotham Slot B 235551 | router `FUN_609b2dec` → `FUN_60abb23c` → verifier `FUN_60ab7f04` — **in the NOR-resident shared code library, not in the slot binary** | bond lookup `FUN_609a532c`, CSRK flag `+0x7b & 4`, anti-replay `+0xdc ≤ received`, CMAC-8 `FUN_609c5e04` over `bond+0x9c`, 8-byte memcmp |

An interim finding of an unauthenticated write in 235551 was refuted: `FUN_608c4a90` is the GATT **client** transaction engine (counter-only, opcode 0x12); the server-side path with verification lives in the shared library. The earlier ambiguous live test ran under gotham, where the handler sits outside the slot binary — which explains why slot-only static reads initially found nothing (see methodological lesson 6).

### 7.3 Untrusted NOR → boot-time parsers (the "interesting" one)

Since HAB only covers executable slots, and we have arbitrary NOR erase/write via the flashloader (§3), anything bruce reads from untrusted NOR at every cold boot is attacker-controlled. This is the only path that would be both untethered and pre-auth. Audited consumers:

1. **Bluetooth bonds/NVRAM parser** (`FUN_60082814` + wire-format layer `FUN_600dfxxx`): this is built on **nanopb with bounds checks compiled in** — evidence: `.rodata` error strings `"array overflow"`, `"bytes overflow"`, `"stream full"`, `"callback failed"` are present (they only emit with bounds-check builds of nanopb). Array entries validated against descriptor `max_count` per-write; all wire reads go through a stream object bounded by `bytes_left`; the NVRAM iterator (`FUN_600dfadc`/`df918`) derives its limits from the **caller's buffer**, never from flash-record headers; page-walk validates tags before advancing.
2. **Stick/trigger calibration** (`FUN_60043834/43ecc/43988`): operates on `std::vector<float>` begin/end (the vector carries its own size from the protobuf), never a fixed array with an assumed count. A lying count only inflates a heap allocation (DoS, not controllable overflow).
3. **KVS typed setters/getters** (`FUN_60066b40/66c28/66ce0`): per-type setters (`FUN_600d71xx`) + capability flag check + invalid-type rejection. No raw `memcpy` of payload into fixed buffers.

**Verdict: no exploitable path from untrusted NOR either.** The consistent defensive pattern across five independent subsystems (HAB, bootloader KVS, vendor RPC, GATT, NVRAM/calibration) strongly suggests systematic internal security review at Google plus a house style of nanopb-with-bounds and capped containers. We're calling this one closed unless/until someone publishes a concrete bug.

### 7.4 EP0 live-USB finding and gotham deep audit (November 2026)

**EP0 vendor OUT length bug (bruce, live USB): DTCM `.data` object map completed statically; bounded and `NULL`-target runtime tests remain open.** Static analysis of the oversized write identifies two kill mechanisms before any multi-tens-of-KB overwrite reaches the power-manager handle (`0x2000D218`): (1) an IRQ-nesting critical-section counter (`uxCriticalNesting = 0xaaaaaaaa`) at `0x20003D68` (offset `0x568` from `+0x190`) — the enter/exit pair (`FUN_60048580`/`FUN_600485c8`, panic path `FUN_600cc5ac`) manages `BASEPRI` IRQ masking and panics/hangs if corrupted; and (2) a live-USB-state window at `0x20003F40–0x20003F5F` consumed by `FUN_60060fe8` / `FUN_6013d4d8`. Static inspection of `bruce` (`337784`) DTCM `.data` (`0x20002740..0x20003fd8`) now resolves gap **(a)** (`ctx` base and every intervening `.data` object between `ctx+0x190` and `0x20003D68`):

| DTCM `.data` range (`bruce` 337784) | Size | Mapped object / subsystem |
|---|---:|---|
| `0x20003670..0x20003853` | 484 B | `vendor_usb.cc` `ctx`: work items `0..3` at `0x64` stride (`+0x000` `0x60077111` `DisableCharging`, `+0x064` `0x600770ed` `EnterShippingMode`, `+0x0c8` `0x600770d9` `RebootFromUsbVendor`, `+0x12c` `0x600db01b` → `0x600772f4` `UpdateGauge`), followed by EP0 buffers `+0x190` (`0x20003800`, 8 B `(build=337784, board_rev)`), `+0x198` (`0x20003808`, 8 B `(active, unlock_level)`), `+0x1a0` (`0x20003810`, 37 B `SsdpUdn` UUID), `+0x1c5` (`0x20003835`, 12 B `SKU`), `+0x1d1` (`0x20003841`, 7 B `ModelId`), `+0x1d8` (`0x20003848`, 2 B `UpdateGauge` SoC `%`), `+0x1dc` (`0x2000384c`, 4 B provisioning state `0..5`) |
| `0x2000385c..0x20003bc7` | 876 B | BLE GATT server descriptor / callback structs (`hid_server.cc` / GATT attribute table pointers) |
| `0x20003bc8..0x20003ca7` | 224 B | BoringSSL initialized `.data` (immediately preceding `"00:00:00:00:00:00"` at `0x20003ca8`) |
| `0x20003ca8..0x20003d63` | 188 B | Broadcom Bluedroid GAP/GATT/BTA callbacks and `"00:00:00:00:00:00"` `BD_ADDR` string (`0x20003cbc..0x20003d60` function pointers) |
| `0x20003d68` | 4 B | FreeRTOS `uxCriticalNesting = 0xaaaaaaaa` (`FUN_60048580`/`FUN_600485c8`, `FUN_600cc5ac`) |
| `0x20003d80..0x20003f4f` | 464 B | Newlib `_impure_ptr` (`0x20003d80 -> 0x20003d84`) and `_reent` (`"C"`, `"ASCII"`) |
| `0x20003f50..0x20003fd7` | 136 B | USB live descriptor / hex scratch string (`"0 00 00 ..."` consumed by `FUN_60060fe8`) |

**Runtime hardware checks & hardware BEE findings (updated 2026-11-15):**
- **2nd-stage Bootloader (`18d1:946b`) & App (`18d1:9400`) EP0 control-path checks:**
  - On `18d1:946b` (`Google Inc. / Bootloader`), querying `EP0 IN` (`0xA1`, `bRequest 0x81..0x8c`, `wLength=64`) returns 64 bytes directly from ITCM address `0x00000000..0x0000003f` (eight `0xdeaddead` NULL-guard words at `0x00..0x1f`, followed by Thumb-2 `.ramfunc` code at `0x20..0x3f`), confirming that the Case (b) `NULL`-buffer behavior described in `issue #1` also exists in the 2nd-stage bootloader's `IN` (`0xA1`) diagnostic path.
  - On `18d1:9400` (`bruce 337784`), static disassembly of `0x60054dc0` confirms `bmRequestType` bit 5 (`0x21`/`0xA1` Class) dispatches through `0x6005505c` while bit 6 (`0x41`/`0xC1` Vendor) dispatches through `0x600d0bc8`. Live USB probing confirmed that bounded `EP0 OUT` (`0x21`, `bRequest=0x89`, `wLength=8..9`) is accepted without `STALL` (mutating volatile `ModelId` state in RAM from `"US/999"` to `""` until reboot), `EP0 OUT` on `0x41` times out, and `EP0 IN` (`0xC1`, `bRequest=0x89`, `wLength=16`) returns `b"US/999\x00\x00\x00\xde\xad\xde\xad\xde\xad\xde"` (exposing `0xdeaddead` ITCM `0x00000000` words past the buffer tail). Architecturally, any EP0 path remains volatile and USB-tethered — it cannot persist across cold boot because HAB re-authenticates flash.
- **USB Host / Tandem mode (`0x6007014c` in `bruce`):** static disassembly confirms `0x6007014c` is a **USB Host** VID/PID matcher (`0x045e`, `0x054c`, `0x057e`, `0x18d1:0x9400`, `0x28de:0x1102/0x1142`) used when a secondary controller is attached to the Stadia Controller's USB-C port in Tandem mode, rather than a device-side mode reachable from a PC host.
- **Hardware Encryption of Writable NOR Partitions — BEE Region 1 (`0x60006000–0x6003ffff`, `AES-128-ECB`, `g = 16`):** surgical NOR captures (`low_256k.bin` via `1fc9:0135` → `15a2:0073`) combined with static disassembly of `bruce` (`0x600717d4` → `0x60067e44` → `0x6005f07c` BEE & `0x6005f310` DCP, OTP key descriptor `0x601091f8` `SW_GP2`/`OTPMK`) prove that firmware protects all 6 writable low partitions (`id=8, 9, 11, 17, 5, 4`, length `0x3a000`) with **i.MX RT106x BEE Region 1 (`AES-128-ECB`)**, enforcing 16-byte write alignment (`g = 16`, `0x6005f320..0x6005f326`). On direct FlexSPI NOR pin reads (`0x402A8100`, outside AHB bus decryption), `bug_reports` (`32` × 16 B blocks), `user_kvs` (`1` active no-seq sector `23` record blocks + `7` standby header blocks), `bt_nvram` (`128` × 16 B blocks), `aux_data_17` (`210` × 16 B blocks), `factory_kvs` (`2` active no-seq sectors `159`/`107` record blocks + `2` standby), and `bootloader_kvs` (`sec[1]` active sequenced `252` record blocks, `sec[2]` active no-seq `136` record blocks + `2` standby) appear as high-entropy 16-byte ciphertext blocks ending cleanly on 16-byte boundaries (`docs/kvs-parser-spec.md` §3.1). Reading `transfer_bug_report` (`op=9`) over live USB (`18d1:9400`, AHB-decrypted) independently corroborates the `bootloader_kvs` layout with plaintext `BootloaderKvsMetadata` (`AppAMeta`/`AppBMeta` `Verified`, `BookkeepMeta: active=1, backup=2`).

**gotham audit coverage.** Full forced decompilation of the Slot B 235551 application binary (330,102 lines, 7,566 functions), the NOR-resident code mapped at XIP `0x60800000+` that it calls into (1,109,540 lines, 28,280 functions — where 235551's ATT server, CMAC-8, and AES-CTR/KDF primitives live; AES S-box at virtual `0x60B169A8` — see §1/§9 item 5 regarding its HAB/CSF bounds relative to nominal `Data / KVS`), and the OTA 282115 image (710,615 lines, 17,134 functions). Audited layers and verdicts:

| Layer | Verdict | Key evidence |
|---|---|---|
| ATT Signed Write 0xD2/CSRK | sane — full CMAC-8 verification | §7.2 |
| Key-store / attribute-table parsers (0x2017/0x2018 key blobs) | sane — post-exploit-only | the one parser with length arithmetic (`FUN_601e4b14` in 282115; `FUN_609ad9cc` in 235551) is fed exclusively by fixed-size internal producers whose length fields are compile-time constants; store entry gated by a 6-byte peer-MAC memcmp |
| protobuf dispatcher family (shared library `FUN_608efc98` chain, 886-line top level) | dead code | no callers, no literal-pool refs, no BL sites in either image |
| NOR persistence layer (`flash_lut.cc`) | sane | erase validates alignment and range before the primitive; writes confined to base `0x60006000` + length `0x3a000` (`0x006000–0x03ffff`, `0x60067e44`) inside BEE Region 1 (`AES-128-ECB`, `g = 16`), erased-cells-only (`0xFF`), rate-limited retry |
| Persistent KVS key registry (`keys.cc`) | not injectable | key table is compile-time rodata at `0x60304b60` — sequential IDs, embedded name pointers, fixed no-erase flags; binary-searched (`FUN_6008f77c`), no runtime writer |

**Net conclusion:** no radio-reachable path to persistent-state corruption exists in any of the three images. Everything that alters persistent storage requires prior code execution, and neither known execution-adjacent entry point (EP0 write, ATT write) provides it.

### 7.5 What this does *not* close

- Physical hardware techniques (voltage/clock glitching, SWD if fuses permit, BEE key extraction) and NXP BootROM USB HID transport (`sdp_hid_callback`, resolved publicly by `tchebb/nxp-sdp-overrun` — §4, §10). Direct cold-boot signing of stock-mode NOR images still requires Google's private RSA-4096 key unless `FIELD_RETURN` is enabled.

---

## 8. Repository contents & reference hashes

### Included in this repository

| Path | Description |
|---|---|
| `README.md` | This technical architecture and security audit reference |
| `docs/kvs-parser-spec.md` | Specification of Google's NOR Key-Value Store (KVS) record format and BEE Region 1 geometry |
| `tools/kvs_parse.py` | Python parser for KVS partitions (`id=9` @ `0x60028000`, `id=5` @ `0x60038000`, `id=4` @ `0x6003c000`) extracted from NOR dumps (`--selftest`, `--json`; supports `g={1,2,4,8,16}` and BEE AES-128-ECB sector classification) |
| `tools/nor_slice_inspect.py` | Offline partition carver and inspector mapping raw NOR slices (`0x000000–0x03ffff` low 256 KiB / `Bootloader B` / `Slot B` / full 16 MiB) to the 13-partition table, integrating FCB/Boot-IVT/`BuildInfo`/KVS/BEE-ECB checks with PII redaction (`--self-test`, `--json`, `--extract-dir`) |
| `tools/ivt_csf_inspect.py` | Offline parser & signed-span auditor for trailing/leading IVT, `BootData`, `BuildInfo`, and HABv4 CSF images (`--selftest`, `--json`) |
| `tools/stadia_diag.py` | Read-only USB HID / EP0 diagnostic tool querying safe vendor IN descriptors (`0x81`, `0x84`, optional `--poll-battery` `0x83`, `0x87`–`0x8a`, `0x8c`) (`--selftest`, `--json`) |
| `tools/udev/99-stadia-controller.rules` | Linux udev permissions for App (`18d1:9400`), 2nd-stage Bootloader (`18d1:946b`), SDP (`1fc9:0135`), and Flashloader (`15a2:0073`) modes |
| `ghidra/DecompAll.java`, `DecompForce.java`, `Xrefs.java`, `MapScatterLoad.java` | Headless Ghidra scripts to reproduce bulk decompilation, xref queries, and `Reset_Handler` FlexRAM/DTCM/ITCM scatter-load mapping on your own dumps |
| `evidence/` | Full reference SHA-256 hashes (`SHA256SUMS.txt` for slot/bootloader/flashloader artifacts), abridged FlexSPI erase summary (`flexspi_erase_verify.log`), and BLE input log (`ble_bruce_input.log`) |

### External tools & reference hashes (not hosted)

Copyrighted firmware binaries and full decompilation corpora are excluded via `.gitignore`. To reproduce locally from your own hardware, use GaryOderNichts's `stadiatool` (sdp/flashloader/dump with canary + auto-recovery) plus the FlexSPI primitives in §3, then run `analyzeHeadless` with `-processor ARM:LE:32:v8T -loader BinaryLoader -loader-baseAddr <addr>` and the scripts in `ghidra/` (or inspect trailing IVT/CSF/BuildInfo headers directly with `python3 tools/ivt_csf_inspect.py <image.bin>`):

- `bootloader_dump.bin`: 131,072 B (sha256 `59ebfd2c…f2ca0`), base `0x60800000`, 547 functions
- `restricted_ivt_flashloader.bin`: 100,672 B, base `0x20002400`, 317 functions
- `bruce_pvt_a_prod_signed.bin` (build 337784): 1,050,984 B, base `0x60040000`, 4,690 functions
- `ota.282115.stable-channel.gotham-pvt-a.214f6fe20f7b993046c77a9245c5805b056882dc.bin` (`gotham` Slot A OTA 282115): 4,163,944 B (sha256 `269bb21160ea6d1366e71bb9c9b148e2782ea967b81c7b6ff038e7d49b61e00f`), XIP base `0x60040000`
- `ota.316382.stable-channel.gotham-pvt-b.da986392604309ea67eab5fa84f747e955f2875c.bin` (`gotham` Slot B OTA 316382): 4,163,944 B (sha256 `4545a7bcc889b911f19409ae363586806922c1423ca519ccdb44c595c1d9c261`), XIP base `0x60840000`
- Additional hardware-dump corpora for reproducing the gotham audit: the Slot B 235551 application (read from NOR offset `0x840000` of a pre-316382 dump) and the shared NOR code library (XIP base `0x60800000`)
- **Provenance warning:** the artifact circulating as `gotham235551.elf` is **not** build 235551 — it is an ELF32 wrapper (single `LOAD` at `0x60040000`) whose file offset `0x1000` embeds a payload byte-identical to the OTA 282115 stable image (sha256 above). Rename it accordingly before using it in analysis; the actual 235551 image only exists in the Slot B region of a hardware dump.

Also hashed in `evidence/SHA256SUMS.txt`: `bruce_dvt_a_dev_signed.bin` (1,050,984 B, the dev-signed build 337784 image whose rejection on production units is described in §4), `gotham235551.elf`, and `flash_head.bin`.

**Methodological lessons (worth more than the addresses):**
1. **Verify primitives with raw captures.** Both the SDP tool and BlueZ lied to us at least once each — parser-level output masked what the wire actually carried. btmon/raw-HID under any parser is the only trustworthy ground truth.
2. **Close by layers, not in block.** The first REV of our notes declared "impossible by design" from partial evidence; three red-team reviews each found an untested assumption (wrong CVE vector, wrong firmware under test, unverified gating claim). Every architectural verdict needs each link measured.
3. **Label every claim demonstrated / probable / not-demonstrated.** The single cheapest technique that caught the most errors.
4. **Recovery before aggression.** With the 10-second SDP recovery validated on day 1, every experiment became cheap to attempt.
5. **A BLE "won't connect" usually isn't the device.** Fresh bond + registered agent + in-window connection solves ~90% of stock-firmware pairing failures on Linux.
6. **A missing handler may live in a shared library.** Searching the Slot B 235551 binary for the 0xD2/CSRK verifier found nothing — the entire ATT server lives in a NOR-resident shared code library the slot calls into. Absence of a handler in the main image is not absence of the handler; map the full XIP space before declaring a path unverified.

---

## 9. What a future researcher still has open

*(Items 1–2 from the original publication — resolving the ATT Signed Write 0xD2/CSRK hardware verdict and the deep audit of gotham — were completed on 2026-11-12; results in §7.2 and §7.4. What remains:)*

1. **The real reading primitive.** CVE-2022-45163 via the actual `CHECK_DATA` DCD timing side channel (NCC Group/fox-it PoC) could yield a slow read path if RT1060 BootROM does not enforce the DCD allowlist on `CHECK_DATA`; testing on hardware and verifying `OCOTP` address admissibility remain open (mostly of research value, since code_exec needs more than a read).
2. **Hardware-class attacks** on HAB: glitching the compare, BEE, SWD (all outside this project's scope).
3. **Custom firmware execution on stock hardware (hardware-verified 2026-11-17):** while direct cold-boot execution of unsigned NOR images on unmodified fuses remains blocked by BootROM HABv4, **`tchebb/nxp-sdp-overrun` (§4, §10)** provides a USB-only SDP (`1fc9:0135`) path via the 3-byte `sdp_hid_callback` overrun in the NXP RT1060 BootROM — supporting **temporary per-boot execution** (via `ROMC` session mode without altering fuses). Hardware verification on this PVT unit confirmed: (a) in `ROMC` session mode (`hab=0x56787856`), BootROM `SDP READ_REGISTER` still masks `0x00200000` (`0x89232389`) and `0x60000000+` (`4323ccdc7eba4de9`), whereas `SDP WRITE_FILE` + `SDP JUMP_ADDRESS` run unsigned IVT images (`csf=0`) in DTCM/OCRAM; (b) loading standard `MIMXRT1062` `ivt_flashloader.bin` (`82,650 B` @ `0x20208200`) re-enumerates `15a2:0073` (`blhost K2.1.0`), enabling full `16 MiB` NOR preservation dumps, `OCOTP` (`0x401f4400`) inspection, and `blhost execute` of custom Cortex-M7 code in DTCM (`0x20000000`), visually confirmed by blinking the **TI LP5562** ring LED on `LPI2C2` (`GPIO_B0_04/05`). Remaining practical work for custom firmware authors centers on full peripheral bring-up (clocks, USB/BLE, BCM43458F HCI) and optionally validating plaintext KVS CRC-16 (`id=9/5/4`) over the AHB bus (`docs/kvs-parser-spec.md` §5).
4. **Unaudited runtime surfaces:** `gotham`'s Wi-Fi-era network stack (Wi-Fi provisioning, TCP/IP, Synapse audio pipeline), runtime parsing across the `BCM43458F` HCI/mailbox boundary (static `BCM43458F` `.hcd` `patchram` and WLAN blobs in both `bruce` and `gotham` were verified inside the HAB-authenticated XIP span via `tools/ivt_csf_inspect.py` in §4.1), and the NXP BootROM mask ROM's internal `hab_rvt` DER/certificate parser (OCOTP/field-return and CSF `WRITE_DATA` allowlisting in the mask ROM were statically audited and closed in §4 / issue #3).
5. ~~NOR hardware capture & `Boot IVT.self` check~~ **Closed (2026-11-15):** surgical hardware dumps captured over `1fc9:0135` → `15a2:0073` (`low_256k.bin`, `bootloader_a_head.bin`, `bootloader_b_head.bin`, `slot_b_head.bin`, `slot_b_ivt_csf.bin`) and analyzed with `tools/nor_slice_inspect.py` / `tools/kvs_parse.py` resolved all open partition/IVT items: (a) `FCB` v1.4.0 (`0x56010400`) on `GigaDevice GD25Q128/GD25LQ128` (`0x17C8`, `USB_ANALOG_DIGPROG = 0x006C0000`), (b) `Boot IVT` (`0x001000`) has **`entry = 0x60801000`** and **`self = 0x60001000`** (closing the `0x60001020` discrepancy), (c) `Bootloader A` (`0x800000`) starts with a matching `0x1000`-byte IVT block while `Bootloader B` (`0x820000`), `id=7`, and `id=10` are completely `0xFF`-erased, (d) `Slot B` (`0x840000`) hosts factory `gotham 235551` (`0x60840000..0x60c20030`), (e) live app-mode Bulk `transfer_bug_report` (`op=9`) and `UnlockChallenge` (`op=1`) succeed pre-unlock (`18d1:9400`), (f) `0x6007014c` was resolved statically as the **USB Host** VID/PID matcher for Tandem secondary-controller input (`0x045e`, `0x054c`, `0x057e`, `0x18d1:0x9400`, `0x28de`), and (g) raw FlexSPI captures of `0x006000..0x03ffff` contain 16-byte **`BEE Region 1` (`AES-128-ECB`, `g = 16`) ciphertext** (`docs/kvs-parser-spec.md` §3.1). Offline CRC-16 validation on plaintext KVS records (`id=9/5/4`) remains applicable only on a CPU-bus (AHB-decrypted) dump or dev-key unit.
6. ~~USB unlock path reconciliation~~ **Closed (2026-11-13; fuse backing resolved 2026-11-15 via issue #3):** §7.1.1 documents the dual-path unlock verified in disassembly — echo-memcmp behind the `(OCOTP fuse 0x26 bit 8 OR IsDfDevice)` gate (the `key_index = 3` / empty-token observation from `docs/kvs-parser-spec.md` §4) alongside the ECDSA P-256 fallback for non-service units. Issue #3 resolved `FUN_600d9934` (`0x26` bit 8) as an on-chip OCOTP silicon fuse read (`FUN_00001084` @ `0x401F4000`, closing the earlier "button combo" sub-item) and confirmed no `bruce` writer exists for KVS key `0x16`.
7. ~~EP0 `issue #1` runtime checks~~ **Verified on hardware (2026-11-15):** static mapping of `bruce` DTCM `.data` (`0x20003670..0x20003fd8` in §7.4) closes the bounded object layout between `ctx` and `uxCriticalNesting` (`0x20003D68`). On hardware, live `EP0 IN` (`0xA1`, `wLength=64`) on 2nd-stage Bootloader `18d1:946b` verified a 64-byte read from ITCM `0x00000000..0x0000003f` (`0xdeaddead` × 8 + `.ramfunc`), while on `18d1:9400`, `EP0 OUT` (`0x21`, `bRequest=0x89`, `wLength=8..9`) mutates volatile RAM state without `STALL` and `EP0 IN` (`0xC1`, `bRequest=0x89`, `wLength=16`) reads `0xdeaddead` ITCM words past the string tail (§7.4). All EP0 state remains volatile in DTCM and cannot persist across reboot.
8. ~~The bootloader's ASN.1/PKCS#7 path was verified only at a coarse level~~ **Closed (2026-11-13):** the bootloader contains no ASN.1 parser at all — all certificate/SRK/signature parsing is delegated to the ROM's HAB `authenticate_image` (`hab_rvt` at `0x0020032c`), and the bootloader-owned surfaces (IVT bounds-check, versioned fixed-size KVS reads, in-place SHA-256, doubly-authenticated update path) were audited function-by-function and found sane (see §4). A bug in the ROM's DER parsing would be an NXP-affecting vulnerability across all HAB-closed RT10xx parts, not a Stadia-specific surface. (The GATT vtable `+0x10` write callbacks originally listed here were fully audited on 2026-11-13 — see §7.2.)
9. ~~`UpdateGauge` (`0x600772f4`) consumer~~ **Closed (2026-11-15):** static disassembly and WebHID reference cross-check confirm `UpdateGauge` is dispatched by EP0 OUT `bRequest 0x83` and populates the 2-byte SoC readback buffer (`ctx+0x1d8` at `0x20003848`) queried by EP0 IN `bRequest 0x84` (§7.1).

---

## 10. Credits & pointer material

- **tchebb** (`https://codeberg.org/tchebb/nxp-sdp-overrun`) — discovery and public documentation of the 3-byte `sdp_hid_callback` (`0x0020ea7e`) buffer-offset overrun in the NXP i.MX RT1060 mask BootROM (`HAB 4.3.7`), enabling pre-`SW_STICKY` unsigned code execution in SDP via `ROMC` session patching or `FIELD_RETURN` eFuse configuration.
- X-15 (`github.com/X-15`, issues #1 and #3) — live-USB discovery and readback verification of the EP0 vendor OUT `wLength` overflow and NULL-buffer ITCM DMA (§7.1 addendum), the `0x8b` bulk-arming lead (issue #2), HID Report `0x05` rumble layout, OCOTP fuse-read resolution for `FUN_600d9934` / `FUN_600d995c` via `FUN_00001084` (§7.1.1), `bruce` KVS `0x16` writer audit, and the i.MX RT1060 mask BootROM field-return / CSF `WRITE_DATA` allowlist audit (§4).
- GaryOderNichts — original Stadia Controller flashloader reverse engineering and `stadiatool` (2023, github.com/GaryOderNichts/StadiaController), which first documented the FlexSPI register access path in Google's restricted flashloader.
- lidskialf.net (Andrew de Quincey) — hardware teardown of the Stadia Controller PCB that physically identified the SoC as NXP i.MX RT1061.
- NXP i.MX RT1060 RM (BootROM/HAB chapters), `fsl_flexspi` SDK sources, u-boot `hab.h` — for ROM contract identification.
- NCC Group / fox-it — CVE-2022-45163 research (real vector is the `CHECK_DATA` timing channel).
- nanopb — its `.rodata` error strings are the smoking gun that identified the NVRAM serialization format.
- Community firmware mirror: `luigimannoni.github.io/stadia-controller-flasher` (WebHID), the only working path to the official Bluetooth-mode image since Google's official flasher went dark.

*Document compiled from the complete project record (boot ROM analysis, 4 red-team review cycles, hardware-verified flash primitives, and a full static audit of the application firmware). Extended November 2026 with the gotham cross-image audit (Slot B 235551, shared NOR code library, OTA 282115) and closure of the 0xD2/CSRK and EP0 questions. Corrections and extensions welcome — if you find a real bug in any of these paths, it will be interesting precisely because this reference documents why the obvious ones aren't there.*
