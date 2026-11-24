# Google Stadia Controller (H2B) — Technical Reverse Engineering Reference

Hardware pinout, NOR partition layout, BootROM/HABv4 security analysis, bare-metal bring-up notes, and offline inspection tools for the **Google Stadia Controller (`H2B`, NXP `MIMXRT1061` + `BCM43458F`)**.

*Compiled November 2026 from static disassembly (`bruce 337784`, `gotham 235551/282115/316382`, bootloader, mask ROM) and live hardware verification on a PVT unit.*

---

## Status Summary

| Area | Status | Reference |
|---|---|---|
| **Hardware pinout** (`ADC1` sticks & triggers, 17 buttons, `LP5562`, `LPI2C1`, `BCM43458F`) | **Hardware-verified** (including active-LOW `GPIO2_10 = 0` for `L2`/`R2` Hall triggers) | [docs/hardware-pinout.md](docs/hardware-pinout.md) |
| **NOR layout (16 MiB), Boot chain & HABv4** | **Mapped & verified** (all 4,096 sectors, `FCB`, `IVT`, `CSF`, `BEE Region 1`) | [docs/boot-and-nor.md](docs/boot-and-nor.md) |
| **Bare-metal execution (`ROMC` DTCM/OCRAM)** | **Working** (USB CDC-ACM on OCRAM `0x20200000`, all inputs + `L2`/`R2`, Classic BT HID `Pro Controller` on macOS) | [docs/bare-metal-bringup.md](docs/bare-metal-bringup.md) |
| **Security audit (`bruce` & `gotham`)** | **Completed** (USB vendor RPC, EP0, BLE GATT, KVS, BootROM HAB) | [docs/security-audit.md](docs/security-audit.md) |
| **KVS record format & BEE Region 1 spec** | **Documented + parser** | [docs/kvs-parser-spec.md](docs/kvs-parser-spec.md) |

---

## Documentation Map

- **[docs/hardware-pinout.md](docs/hardware-pinout.md)** — SoC & memory inventory, `ADC1` stick/trigger table (`L2`/`R2` + `GPIO2_10`), 17-button GPIO map, `BCM43458F` (`LPUART3` + CTS strap + `.hcd`), `LPI2C1`/`LPI2C2` ICs (`BQ25601`, `WM8904`, `TS3A227E`, `BQ2742X`, `LP5562`), haptics, and BLE GATT profile.
- **[docs/boot-and-nor.md](docs/boot-and-nor.md)** — 16 MiB NOR partition table, boot chain, BootROM SDP (`1fc9:0135`) & Google's restricted flashloader (`15a2:0073`), `Reset_Handler` FlexRAM scatter-load map, HABv4 CSF architecture, and CVE applicability.
- **[docs/bare-metal-bringup.md](docs/bare-metal-bringup.md)** — Practical bring-up notes for running custom DTCM firmware via `tchebb/nxp-sdp-overrun` (`ROMC`), `USB1` CDC-ACM in OCRAM, Hall trigger excitation (`GPIO2_10 = 0`), and Classic BT HID (`BCM43458F` + paginated SDP).
- **[docs/security-audit.md](docs/security-audit.md)** — `bruce` vs `gotham` roles, static & live audit of USB vendor RPC / EP0 / BLE GATT / NOR parsers, and remaining open research items.
- **[docs/kvs-parser-spec.md](docs/kvs-parser-spec.md)** — Specification of Google's NOR Key-Value Store (KVS) format and `BEE Region 1` (`AES-128-ECB`) geometry.

---

## Tools & Quick Start

Run the built-in self-tests (requires Python 3, no hardware needed):

```bash
python3 tools/extract_hcd.py --selftest
python3 tools/ivt_csf_inspect.py --selftest
python3 tools/kvs_parse.py --selftest
python3 tools/nor_slice_inspect.py --selftest
python3 tools/stadia_diag.py --selftest
```

### Repository Contents

| Path | Description |
|---|---|
| `docs/` | Modular technical reference (`hardware-pinout.md`, `boot-and-nor.md`, `bare-metal-bringup.md`, `security-audit.md`, `kvs-parser-spec.md`) |
| `firmware/stadia-ram-hello/` | Bare-metal Cortex-M7 DTCM firmware (Switch Pro Controller over Classic BT HID + USB CDC-ACM console; excludes proprietary `.hcd` blob) |
| `tools/extract_hcd.py` | Extracts `BCM43458F` `.hcd` `patchram` (`53,450 B`, 228 HCI packets) from a local `slot_a_bruce.bin` dump into `bcm43458f_hcd.h` |
| `tools/kvs_parse.py` | Parser for NOR KVS partitions (`id=9`, `id=5`, `id=4`; supports `g={1,2,4,8,16}` and BEE AES-128-ECB classification) |
| `tools/nor_slice_inspect.py` | Offline partition carver & inspector for raw NOR dumps (low 256 KiB, slots, or full 16 MiB) with PII redaction |
| `tools/ivt_csf_inspect.py` | Offline parser & signed-span auditor for IVT, `BootData`, `BuildInfo`, and HABv4 CSF images |
| `tools/stadia_diag.py` | Read-only USB HID / EP0 diagnostic tool querying safe vendor IN descriptors (`0x81`, `0x84`, `0x87`–`0x8a`, `0x8c`) |
| `tools/udev/99-stadia-controller.rules` | Linux udev rules for App (`18d1:9400`), Bootloader (`18d1:946b`), SDP (`1fc9:0135`), and Flashloader (`15a2:0073`) |
| `ghidra/` | Headless Ghidra scripts (`DecompAll.java`, `DecompForce.java`, `Xrefs.java`, `MapScatterLoad.java`) |
| `evidence/` | Reference SHA-256 hashes (`SHA256SUMS.txt`), FlexSPI/BLE logs, and live USB CDC-ACM captures (`cdc_i2c_scan.log`, `cdc_l2r2_gpio2_10.log`, `cdc_bt_sdp_hid.log`) |

---

## External Artifacts & Reference Hashes (Not Hosted)

Copyrighted firmware binaries and full decompilation corpora are excluded via `.gitignore`. Reference hashes in `evidence/SHA256SUMS.txt`:

- `bootloader_dump.bin`: `131,072 B` (sha256 `59ebfd2c…f2ca0`), base `0x60800000`, 547 functions
- `restricted_ivt_flashloader.bin`: `100,672 B`, base `0x20002400`, 317 functions
- `bruce_pvt_a_prod_signed.bin` (build `337784`): `1,050,984 B`, base `0x60040000`, 4,690 functions
- `ota.282115.stable-channel.gotham-pvt-a.*.bin` (Slot A OTA `282115`): `4,163,944 B` (`269bb21160ea6d1366e71bb9c9b148e2782ea967b81c7b6ff038e7d49b61e00f`), base `0x60040000`
- `ota.316382.stable-channel.gotham-pvt-b.*.bin` (Slot B OTA `316382`): `4,163,944 B` (`4545a7bcc889b911f19409ae363586806922c1423ca519ccdb44c595c1d9c261`), base `0x60840000`
- **Provenance warning:** `gotham235551.elf` circulating online is an ELF32 wrapper whose payload at `+0x1000` is byte-identical to OTA `282115`, not build `235551` (actual `235551` lives in Slot B of factory hardware dumps).

---

## Credits & References

- **tchebb** (`https://codeberg.org/tchebb/nxp-sdp-overrun`) — 3-byte `sdp_hid_callback` overrun in the NXP i.MX RT1060 mask BootROM (`HAB 4.3.7`), enabling temporary `ROMC` session execution.
- **X-15** (`github.com/X-15`, issues #1–#3) — EP0 vendor OUT `wLength` / NULL-buffer ITCM DMA findings, `0x8b` bulk-arming lead, HID Report `0x05` rumble layout, OCOTP fuse resolution (`FUN_00001084`), and mask BootROM allowlist audit.
- **GaryOderNichts** (`github.com/GaryOderNichts/StadiaController`) — original Stadia Controller flashloader RE and `stadiatool`.
- **lidskialf.net** (Andrew de Quincey) — Stadia Controller PCB teardown identifying the NXP i.MX RT1061 SoC.
- **NCC Group / fox-it** — CVE-2022-45163 (`CHECK_DATA` timing side channel).
- **NXP i.MX RT1060 RM**, `fsl_flexspi` SDK, u-boot `hab.h`, and `luigimannoni.github.io/stadia-controller-flasher`.
