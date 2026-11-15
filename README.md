# Stadia Controller — Technical Architecture & Firmware Reference

**Complete reverse-engineering reference for the Google Stadia Controller**
*Compiled November 2026 from static and live analysis of the device (BootROM SDP probing → bootloader → application firmware). Public, partially artifact-backed, with explicit open items documented below. Shared so future researchers don't have to re-derive any of this.*

> **Scope & ethics note.** This document describes defensive architecture and analysis methodology only. No exploit code, no private keys, no vendor-confidential material (everything below was recovered from public firmware images and standard RE tooling). The device is a discontinued product; research like this is how its 16 MB of NOR stays useful after its cloud service went dark in January 2023 and Google's official flasher page followed it.
>
> **TL;DR for the impatient:** the Stadia Controller is an NXP i.MX RT106x (measured MIMXRT1061, Cortex-M7 crossover) + Broadcom BCM43458F BLE radio, with a strongly locked boot chain. BootROM HAB is CLOSED, bootloader enforces RSA-4096 slot verification against a fused SRK hash, and the audited parsers in the application firmware ("bruce", the 2023 Bluetooth-mode image) use nanopb-with-bounds, strnlen-bounded RPC, and descriptor-checked protobuf. Across the statically audited parser corpus (317 restricted flashloader, 547 bootloader, 4,690 application "bruce" functions discovered by Ghidra), we found no memory-corruption bug in bootloader KVS/slots, USB vendor RPC, BLE GATT Prepare/Execute Write, or NVRAM protobuf. However, important scope limits remain: the **NXP BootROM** (`imxrt1060.bootrom.bin`, `a5d9af17…e58f8e`) was statically audited for OCOTP fuse-write primitives and DCD/CSF `WRITE_DATA` peripheral whitelisting (§4, issue #3), leaving only the ROM's internal `hab_rvt` ASN.1/DER parser alongside the **BCM43458F radio firmware/HCI boundary** and **gotham's Wi-Fi/audio stack** outside the static audit; an EP0 control-transfer length bug (issue #1; §7.1 addendum) still lacks hardware PoC testing for bounded/NULL-target writes (§7.4); and several partition-boundary discrepancies noted in §9 remain to be reconciled against raw flash dumps.
>
> The BootROM was characterized through live SDP/HAB experiments and targeted static disassembly of its OCOTP and CSF Write-Data paths (§3, §4). The previously open BLE path (ATT Signed Write, 0xD2/CSRK) was closed statically across all three firmware images — CMAC-8 signature verification exists in each (§7.2) — and the gotham audit (§7.4) covered its BLE/ATT, key-store, and NOR persistence layers. Once Bluetooth-mode firmware is loaded, the unit works as a standard generic BLE gamepad on Linux/macOS/Windows/Android.

---

## 1. Hardware inventory (verified)

| Component | Detail |
|---|---|
| SoC | NXP **i.MX RT106x** (Cortex-M7 600 MHz "crossover" MCU). `USB_ANALOG_DIGPROG` (0x400D8260) reads `0x006C0000` (0x6C = RT106x family — the register does not distinguish RT1061/1062/1064; the exact variant MIMXRT1061 comes from PCB silkscreen in public teardowns, lidskialf.net) |
| Serial flash | 16 MB QSPI NOR (`XIP`-mapped at `0x60000000`, SPI via FlexSPI). Google's WebUSB/WebHID flasher (`zatanna`) accepts two JEDEC variants: **GigaDevice `GD25Q128`/`GD25LQ128` (`0x17C8`, `"Giga-16m"`)** and **Winbond `W25Q128JW` (`0x17EF`, `"Winbond-16m"`)** |
| Bluetooth radio | Broadcom **BCM43458F** (BT 4.2 + BLE; plus 802.11ac SDIO WLAN under `gotham`). Patchram string: `;BCM43458F 37.4MHz Google Gotham BT4.2 [Version: 0054.0161]`. Host loads it via HCI patchram at boot |
| Crypto anchor | HAB (High-Assurance Boot) in mask ROM, RSA-4096/SHA-256; SRK hash fused in OCOTP (not in flash) |
| USB IDs | App mode `18d1:9400` (Google), BootROM SDP `1fc9:0135`, Google flashloader `15a2:0073` |
| BLE identity | Name `StadiaFXXXX-XXXX` (suffix = last 2 bytes of MAC), pure LE (`Flags 0x06` — BR/EDR not supported). Advertising window ≈ 2 min after pairing mode (orange LED blink), then sleeps — re-enter with 4+ s Stadia-button hold |

Serial example referenced throughout: `9C020YCAC6XXXX` (production build; serial masked in this public copy). Per `zatanna`, Google's flasher classifies serial prefixes as `91..94` = unsupported early EVT/proto units, `95..97` or `9800..9808` = `DVT` (`bruce_dvt_a_dev_signed.bin`), and `9809+` / `99+` / `9C+` = `PVT` (`bruce_pvt_a_prod_signed.bin`).

### Firmware layout in NOR (16 MB; physical offset vs XIP address — offsets for stadiatool/flash tools, XIP for Ghidra/execution)

| Region | Physical NOR offset | XIP address | Content |
|---|---|---|---|
| FCB | `0x000000–0x000fff` | `0x60000000–0x60000fff` | FlexSPI Configuration Block (LUT at `+0x080`) |
| Boot IVT | `0x001000` | `0x60001000` | Initial IVT + boot data read by the mask ROM (`entry` 0x60800010 → bootloader, no mini stage-1) |
| Application A | `0x040000–0x7fffff` | `0x60040000–0x607fffff` | `7.75 MiB` (`0x7c0000`, `8,126,464 B`, flasher ID `1`). Holds `bruce` (`1,050,984 B`, signed `0x60040000–0x6013f030`) or `gotham` OTA (`4,163,944 B`, signed `0x60040000–0x60437030`) |
| Bootloader A | `0x800000–0x81ffff` | `0x60800000–0x6081ffff` | Google second-stage bootloader A (`128 KiB`, `0x20000`, flasher ID `3`), own IVT+CSF |
| Bootloader B | `0x820000–0x83ffff` | `0x60820000–0x6083ffff` | Redundant second-stage bootloader B (`128 KiB`, `0x20000`, flasher ID `4`) for atomic rollback |
| Application B | `0x840000–0xffffff` | `0x60840000–0x60ffffff` | `7.75 MiB` (`0x7c0000`, `8,126,464 B`, flasher ID `2`) nominal flasher window; hosts `gotham` factory image (`4,163,944 B` / `0x840000–0xc38967` in `316382`), with upper tail space past `0xc38968` for NVRAM/KVS/calibration/factory partitions |

**Partition-extent reconciliation & slot header contract (resolved statically against Google's `zatanna` flasher and `gotham` OTA 282115 / 316382 images; see §9 item 5):**

- **Partition table (`zatanna`):** Application A (`0x60040000`, `0x7c0000 B`) and Application B (`0x60840000`, `0x7c0000 B`) are symmetric `7.75 MiB` slots framing the dual `128 KiB` bootloaders (`0x60800000` Bootloader A, `0x60820000` Bootloader B). What earlier partial-dump notes labeled a `"NOR-resident shared code library"` at `0x60800000+` (`0x609b2dec..0x60B169A8+`) was the upper ~3 MiB of the monolithic `gotham` Slot B binary (`4,163,944 B`, vs `bruce`'s `1,050,984 B` BLE-only footprint) truncated when only 1 MiB was extracted. Exact KVS/NVRAM/calibration partition offsets inside the unused tail remain to be captured from a raw full-NOR hardware dump (`§9` item 5).
- **`BuildInfo` metadata block (`slot_base + 0x400`, `256 B`):** every application image carries a fixed 256-byte descriptor at `+0x400` (`0x60040400` / `0x60840400`) validated by both the flasher and `firmware_image_upload.cc`: header magic `0x747315a2` at `+0x00`, version `1` at `+0x04`, size `0x100` at `+0x08`, type `2` at `+0x0c`, flash size `0x01000000` (`16 MiB`) at `+0x10`, `uint32_le` build number at `+0x14` (`337784` in `bruce`, `282115` / `316382` in `gotham`), and footer magic `0x4786cd88` at `+0xfc`.
- **Trailing HABv4 IVT pointer (`*(slot_base + 0x1c)`):** Cortex-M7 vector table word 7 (`+0x1c`) stores the XIP address of the slot's trailing HABv4 IVT (`0x6013f000` in `bruce`, `0x60437000` in `gotham-pvt-a`, `0x60c37000` in `gotham-pvt-b`), explaining why bootloader `FUN_6080200c` dereferences `slot_base + 0x1c`. Each trailing `boot_data` declares `length = 0x007c0000`, while `AUTHENTICATE_DATA` covers `base_vma .. csf_ptr` (`0x0ff030 B` in `bruce`, `0x3f7030 B` in `gotham`; inspectable offline with `tools/ivt_csf_inspect.py`).
- **`SRC_GPR5/6/7` reset handoff (`0x400F8030..0x400F8038`):** `zatanna` clears `SRC_GPR5..7`, writes `1` (Slot A) or `2` (Slot B) to `SRC_GPR7` (`0x400F8038`), and resets the chip to steer the bootloader to the newly flashed slot; `Reset_Handler` checks/clears `SRC_GPR6` (`0x400F8034`) for fast/warm-reset handling.

---

## 2. Boot chain

```
Mask ROM (HAB4.1)                                  — NXP code, non-updatable
  → reads the fixed IVT at 0x60001000 (flash offset 0x1000) [early ROM notes, raw flash_head.bin bytes not verified in repo]:
    header    0x412000D1
    entry     0x60800010   ← direct pointer into the Google bootloader — no mini stage-1
    dcd       0x00000000
    boot_data 0x60001020 (start 0x60000000, length 0x01000000 = whole 16 MB XIP space)
    self      0x60001020   ← [DOC-DISCREPANCY: NXP HABv4 defines self == IVT address (0x60001000); verify against raw flash_head.bin]
    csf       0x60818000   (the bootloader's own CSF, next to it at 0x800000)
  → verifies bootloader IVT+CSF @ 0x60800000
Google bootloader (128 KB @ flash offset 0x800000) — 547 functions decompiled
  → checks slot SHA-256 vs KVS metadata (AppAMeta/AppBMeta/RecoveryMeta) when KVS entries exist
  → invokes ROM HAB to verify slot IVT+CSF (key IMG3_1_usr)
  → jumps to active slot image (Slot A bruce @ 0x60040000, or fallback Slot B @ 0x60840000)
bruce / gotham (application)                        — 4,690 functions decompiled
  → loads BCM43458F patchram, bring-up board/USB/BLE, runs stack + game logic
```

**Recovery path (works on any unit):** hold Stadia button ~10 s while plugging USB → unit enumerates as BootROM SDP `1fc9:0135`, accepting `WRITE_FILE` to load a flashloader over HID. This is the permanent escape hatch — every experiment below was done with this safety net.

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

| Section | `bruce` (`337784`, Slot A) | `gotham-pvt-a` (`282115`, Slot A) | `gotham-pvt-b` (`316382`, Slot B) |
|---|---|---|---|
| **ITCM `.ramfunc`** (copy from Flash LMA `+0x81c`) | `0x00000000–0x0000bdf8` (`48,632 B`, LMA `0x6004081c`) | `0x00000000–0x0001e128` (`123,176 B`, LMA `0x6004081c`) | `0x00000000–0x0001e128` (`123,176 B`, LMA `0x6084081c`) |
| **DTCM `.bss_low`** (zero-filled) | `0x20000000–0x20002740` (`10,048 B`) | `0x20000000–0x20002760` (`10,080 B`) | `0x20000000–0x20002760` (`10,080 B`) |
| **DTCM `.data`** (copy from Flash LMA) | `0x20002740–0x20003fd8` (`6,296 B`, LMA `0x6013d5a8`) | `0x20002760–0x20006dfc` (`18,076 B`, LMA `0x60432778`) | `0x20002760–0x20006dfc` (`18,076 B`, LMA `0x60c32670`) |
| **DTCM `.noinit`** (retained gap) | `0x20003fd8–0x20004020` (`72 B`) | `0x20006dfc–0x20007020` (`548 B`) | `0x20006dfc–0x20007020` (`548 B`) |
| **DTCM `.bss_high`** (zero-filled) | `0x20004020–0x2002a824` (`157,700 B`) | `0x20007020–0x2003e684` (`226,916 B`) | `0x20007020–0x2003e684` (`226,916 B`) |
| **DTCM `.stack`** (`MSP`, filled `0xaabbaabb`) | `0x2002a828–0x2002b828` (`4,096 B`) | `0x2003e688–0x2003f688` (`4,096 B`) | `0x2003e688–0x2003f688` (`4,096 B`) |

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

**Consequence (assuming intact NXP mask ROM HABv4): cold-boot execution of unsigned code has no known software path.** Writing arbitrary flash outside active verification was never the hard part (see §3) — getting it *executed* is.

### 4.1 HABv4 CSF layout & `BCM43458F` co-processor coverage (verified offline)

All five reference signed images inspected with `tools/ivt_csf_inspect.py` share the **identical 4-key RSA-4096 SRK table** (`table_sha256 = 4f69081a259e648a...`, fused OCOTP `SRK_HASH = 79f828294f4d3be9c1e570867878b7af4f17918a5f9955c1a9bee0512a00ff50`), differing only in `INSTALL_SRK` key selection (`src_idx = 0` / `SRK1`, revoked in OCOTP `SRK_REVOKE` on PVT units, vs `src_idx = 2` / `SRK3`):

| Image | Base VMA | IVT (`+off`) | CSF (`+off`) | `SRK` idx | `AUTHENTICATE_DATA` span |
|---|---|---|---|---|---|
| `restricted_ivt_flashloader.bin` (`100,672 B`) | `0x20000000` | `0x20000400` (`+0x400`) | `0x20017000` (`+0x17000`, `80 B` cmd stream + `UNLOCK eng=0x21 feat=0x2`) | `2` (`SRK3`) | `[0x20000000..0x20017000)` (`0x17000 B`) |
| `bruce_dvt_a_dev_signed.bin` (`1,050,984 B`) | `0x60040000` | `0x6013f000` (`+0xff000`) | `0x6013f030` (`+0xff030`, `72 B` cmd stream) | `0` (`SRK1`) | `[0x60040000..0x6013f030)` (`0x0ff030 B`) |
| `bruce_pvt_a_prod_signed.bin` (`1,050,984 B`) | `0x60040000` | `0x6013f000` (`+0xff000`) | `0x6013f030` (`+0xff030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60040000..0x6013f030)` (`0x0ff030 B`) |
| `ota.282115...gotham-pvt-a.bin` (`4,163,944 B`) | `0x60040000` | `0x60437000` (`+0x3f7000`) | `0x60437030` (`+0x3f7030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60040000..0x60437030)` (`0x3f7030 B`) |
| `ota.316382...gotham-pvt-b.bin` (`4,163,944 B`) | `0x60840000` | `0x60c37000` (`+0x3f7000`) | `0x60c37030` (`+0x3f7030`, `72 B` cmd stream) | `2` (`SRK3`) | `[0x60840000..0x60c37030)` (`0x3f7030 B`) |

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

Report Map content: 15 buttons (`95 0f` — A B X Y, L1 R1 L3 R3, menu, capture, Google Assistant, Stadia, L2 R2), hat switch (8-way), 2 sticks (X/Y + Z/Rz), analog triggers via `09 c5` (Brake/RL2) and `09 c4` (Accelerator/RR2), Consumer page volume/play-pause, and battery-strength display output. This is a **clean HID gamepad descriptor** with nothing Switch/Nintendo in it.

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
| `7` (`0x87`) | Refresh `ctx+0x1a0` from its backing store, then return it | copy/measure `strnlen`-bounded at `0x25` (`36` chars + NUL) |
| `8, 9` (`0x88, 0x89`) | Return pointers to `ctx+0x1c5` (`BruceMfgDate`) / `ctx+0x1d1` (`DeviceColor`) | `strnlen`-bounded (`0xc` / `7` bytes), reject `len ≥ max` |
| `0xa` (`0x8a`) | Enforces IN direction (`req.setup < 0`), then binary lookup in 6-entry table `{opcode u32, char* name}` @ `0x6010a0dc` keyed on `ctx+0x1dc` (`MissingProvisioningData`, `NeedsFdr`, `FailedToReadFuses`, `ReadyFor{Developer,InternalUser,End}Use`) | returns ASCII state string capped at `0x3f` (`63` chars) |
| `0xb` (`0x8b`) | Signals vendor provider record `0x2001EDA8` via `FUN_60077744` → `FUN_600926b8` to wake/arm the bulk vendor task (`req.buffer` unset) | — |
| `0xc` (`0x8c`) | Calls `FUN_60077720` (`VendorUsbTask != NULL`) and `FUN_60077730` (`*(VendorUsbTask + 0x113c)` = `unlock_level`), writing them to `ctx+0x198` | fixed `8` bytes |
| default | Logs `"Invalid vendor RPC request: "` (`req.buffer` unset) | — |

Every length check is `strnlen`-style (`FUN_600db002` is literally a bounded strlen) with explicit upper bound rejection. **No overflow.** Scope note: this is a **static audit** of the decompiled dispatcher; in the live unit the unauthenticated USB vendor endpoint is a factory/provisioning channel whose bulk interface does not arm by default in normal user operation (the arming precondition — an EP0 `0xA1 0x8b` class IN — was demonstrated on 2026-11-13, issue #2). Note for researchers: the dispatcher's "invalid opcode" log is a live oracle — unknown verbs produce identifiable log output, making fuzzing measurable (we just found nothing to fuzz into).  

**Addendum (2026-11, issue #1): the EP0 control path into this dispatcher is not covered by the audit above.** The USB setup handler (FUN_60054dc0) dispatches class and vendor control requests to the same dispatcher, then runs the OUT data stage with the host's wLength as the receive length, without comparing it to the length the dispatcher declared for the request. Consequences, confirmed statically on bruce and on gotham 235551 (twin handler at 0x60076e5c, byte-identical sequence): (a) an OUT transfer on a read-mapped bRequest (e.g. 0x81, declared length 8 at ctx+0x190) writes as many bytes as the host sends, across the adjacent context fields, and the serial field at ctx+0x1c5 sits 0x35 bytes into that range; (b) dispatcher cases that return success without setting a buffer (0x80, 0x82, 0x83, 0x85, 0x86) leave the request buffer NULL, so an OUT data stage receives at address 0. The per-case bounds in the table above describe the dispatcher's own copies and are unaffected; the bug is in the setup handler's data stage, which this audit had not covered. Hardware demonstration by the reporter (issue #1); maintainer verification is static, with reproduction PoCs written from the code paths but not yet run on a maintainer unit.

#### 7.1.1 Bulk vendor channel: message schema, command table, and the unlock gate (2026-11-13, live-verified)

The bulk interface is a separate protocol above the EP0 verbs, served by the `vendor_usb_task` (strings cluster `0x60124528+`, streaming nanopb decoder with its own error strings). The request message is protobuf: **outer field 1 = request id** (echoed in the response, any u32 varint), **outer field 2 = a nested message** whose fields land in a request struct as **kind** (`+8`, u32) and **op** (`+0x10`, u8), with a length-prefixed bytes field at `+0x14/+0x18` (token submission). Three kinds exist (inner field 1):

| kind | Meaning |
|---|---|
| 2 | **unlock token submission** — see gate below |
| 3 | **RPC** — `op 1 = unlock-challenge generation` (gated at `FUN_60077948`, string built at `ctx+0x1380` from UUID at `0x2000d1d5` + runtime counter, stored at `ctx+0x135c`); `ops 2, 8, 9, 10` bypass unlock (`FUN_60077bec`); remaining ops and kinds `4..10` dispatch after unlock through the 16-entry table at `0x6010a174` (`FUN_60077a48`) |

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

**The unlock gate — dual-path (reconciled 2026-11-13; OCOTP fuse backing & `unlock_level` reconciled 2026-11-15 via issue #3 and static disassembly).** Every gated provider call passes `FUN_60077948(task, msg, required_mask=0x3e8)`: `bics.w r3, required_mask, [VendorUsbTask + 0x113c]` (`0x60077966`) requires `required_mask` bits to be present in `VendorUsbTask->unlock_level` at offset `+0x113c` inside the heap-allocated `0x17c0`-byte `VendorUsbTask` object (`*(0x2001ee0c)`). In constructor `0x60077668`, `+0x113c` is initialized to **`0`** (`0x600776ae`), and only successful kind-2 unlock sets it to **`0xFFFFFFFF`** (`0x60077eaa`); `bRequest 0x8c` returns `(VendorUsbTask != NULL, *(VendorUsbTask + 0x113c))` via `FUN_60077720`/`FUN_60077730`. *(Historical note: an earlier draft cited `0x600c5c21` as an allow-mask at `ctx+0x113c`; `0x600c5c21` = `FUN_600c5c20 | 1` is actually an entry at `0x60118bcc` inside Broadcom Bluedroid's `bta_dm_action` table, and `FUN_600a3f40` is a `bta_dm` routine writing `bta_dm_cb + 0x1118`.)* Locked requests log `"Device locked for "` (rate-limited to once per 60 s). Kind 2 (token submission) has **two verification paths, selected by `FUN_600d7cdc`** (disasm `0x60077d92`):

- **Echo / serial-token path (factory/provisioning-gated):** the gate passes if **either** an **on-chip OCOTP silicon fuse** is set (`FUN_600d9934` → `FUN_60071348(0x26)` → ITCM `FUN_00001084(0x401F4000, 0x26, &out, 4)` — a textbook i.MX RT1060 OCOTP read from controller base `0x401F4000` that polls `HW_OCOTP_CTRL.BUSY`, writes fuse index `0x26` to `HW_OCOTP_CTRL_SET`, sets `HW_OCOTP_READ_CTRL.READ_FUSE`, reads `HW_OCOTP_READ_FUSE_DATA` at `+0x40`, and tests bit 8; *not* a companion-chip button-combo register as earlier notes assumed) **or** the unit is factory-provisioned (`FUN_600d72ec(0x16,…)` = `IsDfDevice`, KVS-backed via `FUN_601010c8`). Enumerating every KVS writer in `bruce` (`FUN_60101198` and typed put-by-id wrappers `0x600d7140..0x600d7250`) shows **zero call sites in `bruce` ever write key `0x16`** — the gate is strictly read-only in application firmware. Gate pass → the token is accepted by a plain **echo / serial compare**: same length as the UUID/serial string at OCRAM `0x2000d1d5` (`strlen`) and `memcmp(token, 0x2000d1d5)` (`0x6013d168`) equality → **mask set to `0xFFFFFFFF` directly, no cryptography** (branch `0x60077da2–0x60077db0` → `0x60077e9e`). This reconciles the earlier triage observation of a `"successful empty-token unlock"` on `key_index = 3` (`A OR B` gate, echo memcmp against `SsdpUdn`): an unseeded/empty string plus an empty token is a trivially equal echo pair.
- **ECDSA path (remote/factory-signed):** if the gate fails (end-user unit with OCOTP fuse `0x26` bit 8 and KVS key `0x16` clear), kind 2 falls through to `0x60077db2`. It builds a SHA-256 digest (`SHA256_Init` `0x6008ee14`; three `SHA256_Update` `0x600775ac` calls over `0x2000d1d5` UUID/UDN, `0x2000d168` device-info, and the `snprintf`-formatted challenge nonce from `ctx+0x135c` via `0x600cdcc4`; `SHA256_Final` `0x600ec016`), selects one of two embedded **NIST P-256 (`prime256v1`) PEM public keys** (`0x60124756` / `0x60124808`; strings `"Failed to configure public key bio"`, `"Failed to load public key"`, `"EC verification failed."`) at `0x60077dc4` via `FUN_600d7cc4` → `FUN_600d995c` (which reads **OCOTP fuse field `6`**, `(val & 0xC00000) == 0xC00000`, choosing prod vs non-prod key — correcting the earlier "power-state-dependent" note), and verifies the signature through the BoringSSL ECDSA core (`0x60084e8c` → `0x6008d03c`). Success (`r0 == 1` and error accumulator `r6 == 0` at `0x60077f74`/`0x60077e98`) → same mask `0xFFFFFFFF`.

On success the full provider table — including the firmware upload writer — becomes callable. **Live-verified 2026-11-13 (PoC `bulk_unlock_echo2.py`):** on this ReadyForEndUserUse unit the unlock is unreachable through a **double lock**: (1) challenge generation (RPC kind 3/op 1) itself passes through the same permission gate with a required mask of `0x3e8`, which `VendorUsbTask+0x113c` (`unlock_level`, initialized to `0` by constructor `0x600776ae` and tested via `bics.w r3, 0x3e8, r3` in `FUN_60077948`) does not contain — the request times out (the task logs `"Device locked for "` and never responds), so no challenge is ever stored at `ctx+0x135c`; and (2) kind 2 without a pending challenge returns a clean status-4 rejection (`ctx+0x135c == NULL`) before any token verification — neither the echo nor the ECDSA path is reachable. Note also that challenge generation computes a **key_index** (`ctx+0x1422`: `3` = OCOTP fuse `0x26` bit 8 / `IsDfDevice` gate passed → echo token; `1`/`2` = OCOTP fuse `6`-selected prod vs non-prod ECDSA variants) *before* the mask gate, which is the origin of the historical `key_index = 3` / empty-token observation — it was recorded on a unit whose provisioning state passed that gate. **Security consequence, corrected:** the bulk channel is *not* gated by Google's EC key alone, nor by a physical button combo; both legs of `FUN_600d7cdc` are manufacturing/flash-provisioning gates (on-chip OCOTP fuse `0x26` bit 8 or unsigned-NOR KVS key `0x16` with no writer in `bruce`). On retail `ReadyForEndUserUse` units (`EP0 0xA1 bRequest 0x8a`, keyed on `ctx+0x1dc`), the unlock is blocked even earlier by the permission-mask gate on `RPC kind 3 / op 1` (`VendorUsbTask+0x113c` starts at `0`, missing `0x3e8`) before any cryptography is consulted: even Google's ECDSA private key could not complete an unlock on a retail unit without first satisfying that mask gate. **But the terminal gate for custom firmware is unchanged:** even fully unlocked, `firmware_image_upload` only writes flash; cold-boot execution still requires passing BootROM/bootloader HAB RSA-4096 verification.

All live probes for this section were read-only (getters, challenge generation, kind-error paths); the shipping verb and the firmware-upload provider were never invoked.

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
| `0x20003670..0x20003853` | 484 B | `vendor_usb.cc` `ctx`: work items `0..3` at `0x64` stride (`+0x000` `0x60077111` `DisableCharging`, `+0x064` `0x600770ed` `EnterShippingMode`, `+0x0c8` `0x600770d9` `RebootFromUsbVendor`, `+0x12c` `0x600db01b` → `0x600772f4` `UpdateGauge`), followed by EP0 buffers `+0x190` (`0x20003800`, 8 B `(build=337784, board_rev)`), `+0x198` (`0x20003808`, 8 B `(active, unlock_level)`), `+0x1a0` (`0x20003810`, 37 B serial), `+0x1c5` (`0x20003835`, 12 B `BruceMfgDate`), `+0x1d1` (`0x20003841`, 7 B `DeviceColor`), `+0x1d8` (`0x20003848`, 2 B `UpdateGauge` SoC `%`), `+0x1dc` (`0x2000384c`, 4 B provisioning state `0..5`) |
| `0x2000385c..0x20003bc7` | 876 B | BLE GATT server descriptor / callback structs (`hid_server.cc` / GATT attribute table pointers) |
| `0x20003bc8..0x20003ca7` | 224 B | BoringSSL initialized `.data` (immediately preceding `"00:00:00:00:00:00"` at `0x20003ca8`) |
| `0x20003ca8..0x20003d63` | 188 B | Broadcom Bluedroid GAP/GATT/BTA callbacks and `"00:00:00:00:00:00"` `BD_ADDR` string (`0x20003cbc..0x20003d60` function pointers) |
| `0x20003d68` | 4 B | FreeRTOS `uxCriticalNesting = 0xaaaaaaaa` (`FUN_60048580`/`FUN_600485c8`, `FUN_600cc5ac`) |
| `0x20003d80..0x20003f4f` | 464 B | Newlib `_impure_ptr` (`0x20003d80 -> 0x20003d84`) and `_reent` (`"C"`, `"ASCII"`) |
| `0x20003f50..0x20003fd7` | 136 B | USB live descriptor / hex scratch string (`"0 00 00 ..."` consumed by `FUN_60060fe8`) |

**Remaining runtime hardware checks (§9 item 7):** bounded short writes into `ctx+0x190..0x20003d63` (BLE GATT / Bluedroid callback structs), and Case (b) from the §7.1 addendum (`0x80, 0x82, 0x83, 0x85, 0x86` leaving the receive buffer `NULL`, writing at address `0x00000000` in Cortex-M7 ITCM space), remain to be tested against hardware MPU/DMA behavior. Architecturally, any EP0 path remains volatile and USB-tethered — it cannot persist across cold boot because HAB re-authenticates flash.

**gotham audit coverage.** Full forced decompilation of the Slot B 235551 application binary (330,102 lines, 7,566 functions), the NOR-resident code mapped at XIP `0x60800000+` that it calls into (1,109,540 lines, 28,280 functions — where 235551's ATT server, CMAC-8, and AES-CTR/KDF primitives live; AES S-box at virtual `0x60B169A8` — see §1/§9 item 5 regarding its HAB/CSF bounds relative to nominal `Data / KVS`), and the OTA 282115 image (710,615 lines, 17,134 functions). Audited layers and verdicts:

| Layer | Verdict | Key evidence |
|---|---|---|
| ATT Signed Write 0xD2/CSRK | sane — full CMAC-8 verification | §7.2 |
| Key-store / attribute-table parsers (0x2017/0x2018 key blobs) | sane — post-exploit-only | the one parser with length arithmetic (`FUN_601e4b14` in 282115; `FUN_609ad9cc` in 235551) is fed exclusively by fixed-size internal producers whose length fields are compile-time constants; store entry gated by a 6-byte peer-MAC memcmp |
| protobuf dispatcher family (shared library `FUN_608efc98` chain, 886-line top level) | dead code | no callers, no literal-pool refs, no BL sites in either image |
| NOR persistence layer (`flash_lut.cc`) | sane | erase validates alignment and range before the primitive; writes confined to the `0x6000–0x3A000` window, erased-cells-only (`0xFF`), rate-limited retry |
| Persistent KVS key registry (`keys.cc`) | not injectable | key table is compile-time rodata at `0x60304b60` — sequential IDs, embedded name pointers, fixed no-erase flags; binary-searched (`FUN_6008f77c`), no runtime writer |

**Net conclusion:** no radio-reachable path to persistent-state corruption exists in any of the three images. Everything that alters persistent storage requires prior code execution, and neither known execution-adjacent entry point (EP0 write, ATT write) provides it.

### 7.5 What this does *not* close

- Any hardware attack (glitching, SWD if fuses permit, BEE key extraction).
- The Switch 2 side: Nintendo's native controller protocol is BLE-proprietary (manufacturer data with company `0x0553`, custom GATT, no standard SMP), and no stock path makes the Stadia speak it. Wake-beacon format is public (`mfg 0x0553`, VID `0x057E`, bonded-controller PID, byte `0x0B=0x81`, host MAC reversed) but **must originate from an already-bonded MAC** — a software-only bridge violates both "no extra hardware" and stock-firmware constraints.

---

## 8. Repository contents & reference hashes

### Included in this repository

| Path | Description |
|---|---|
| `README.md` | This technical architecture and security audit reference |
| `docs/kvs-parser-spec.md` | Specification of Google's NOR Key-Value Store (KVS) record format |
| `tools/kvs_parse.py` | Python parser for KVS partitions extracted from NOR dumps |
| `tools/ivt_csf_inspect.py` | Offline parser & signed-span auditor for trailing/leading IVT, `BootData`, `BuildInfo`, and HABv4 CSF images (`--selftest`, `--json`) |
| `tools/stadia_diag.py` | Read-only USB HID / EP0 diagnostic tool querying safe vendor IN descriptors (`0x81`, `0x84`, optional `--poll-battery` `0x83`, `0x87`–`0x8a`, `0x8c`) (`--selftest`, `--json`) |
| `tools/udev/99-stadia-controller.rules` | Linux udev permissions for App (`18d1:9400`), SDP (`1fc9:0135`), and Flashloader (`15a2:0073`) modes |
| `ghidra/DecompAll.java`, `DecompForce.java`, `Xrefs.java`, `MapScatterLoad.java` | Headless Ghidra scripts to reproduce bulk decompilation, xref queries, and `Reset_Handler` FlexRAM/DTCM/ITCM scatter-load mapping on your own dumps |
| `evidence/` | Full reference SHA-256 hashes (`SHA256SUMS.txt` for slot/bootloader/flashloader artifacts — no KVS/full-16MB NOR dump yet), abridged FlexSPI erase summary (`flexspi_erase_verify.log`), and BLE input log (`ble_bruce_input.log`) |

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
3. **Switch 2 protocol emulation** on the radio itself requires speaking Nintendo's proprietary BLE from the controller's own BT chip — not reachable with signed stock firmware; would need either a custom image (HAB blocks) or a hardware transplant. The beacon/wake spec is however fully documented publicly (ndeadly, alexvnesta) and reproducible from any other BLE-capable device you control.
4. **Unaudited runtime surfaces:** `gotham`'s Wi-Fi-era network stack (Wi-Fi provisioning, TCP/IP, Synapse audio pipeline), runtime parsing across the `BCM43458F` HCI/mailbox boundary (static `BCM43458F` `.hcd` `patchram` and WLAN blobs in both `bruce` and `gotham` were verified inside the HAB-authenticated XIP span via `tools/ivt_csf_inspect.py` in §4.1), and the NXP BootROM mask ROM's internal `hab_rvt` DER/certificate parser (OCOTP/field-return and CSF `WRITE_DATA` allowlisting in the mask ROM were statically audited and closed in §4 / issue #3).
5. **NOR hardware capture & `Boot IVT.self` check:** the partition table (`Slot A` `0x040000..0x800000`, `Slot B` `0x840000..0x1000000`, `Bootloader A/B` `0x000000`/`0x800000` × `0x20000 B`), `BuildInfo` header, and trailing IVT/CSF layout across all 5 images are now statically resolved (§1, §4.1, `tools/ivt_csf_inspect.py`). What remains requires live flash hardware: capturing the first real `Data / KVS` dump (`tools/kvs_parse.py`) and verifying `Boot IVT.self` (`0x60001020` vs `0x60001000`) directly from raw `flash_head.bin` bytes.
6. ~~USB unlock path reconciliation~~ **Closed (2026-11-13; fuse backing resolved 2026-11-15 via issue #3):** §7.1.1 documents the dual-path unlock verified in disassembly — echo-memcmp behind the `(OCOTP fuse 0x26 bit 8 OR IsDfDevice)` gate (the `key_index = 3` / empty-token observation from `docs/kvs-parser-spec.md` §4) alongside the ECDSA P-256 fallback for non-service units. Issue #3 resolved `FUN_600d9934` (`0x26` bit 8) as an on-chip OCOTP silicon fuse read (`FUN_00001084` @ `0x401F4000`, closing the earlier "button combo" sub-item) and confirmed no `bruce` writer exists for KVS key `0x16`.
7. **EP0 `issue #1` runtime checks:** static mapping of `bruce` DTCM `.data` (`0x20003670..0x20003fd8` in §7.4) now closes the bounded object layout between `ctx` and `uxCriticalNesting` (`0x20003D68`). What remains is runtime verification on hardware (`tools/stadia_diag.py` for read-only sanity + controlled PoCs for bounded short writes and Case (b) `NULL` / address-`0` ITCM DMA behavior).
8. ~~The bootloader's ASN.1/PKCS#7 path was verified only at a coarse level~~ **Closed (2026-11-13):** the bootloader contains no ASN.1 parser at all — all certificate/SRK/signature parsing is delegated to the ROM's HAB `authenticate_image` (`hab_rvt` at `0x0020032c`), and the bootloader-owned surfaces (IVT bounds-check, versioned fixed-size KVS reads, in-place SHA-256, doubly-authenticated update path) were audited function-by-function and found sane (see §4). A bug in the ROM's DER parsing would be an NXP-affecting vulnerability across all HAB-closed RT10xx parts, not a Stadia-specific surface. (The GATT vtable `+0x10` write callbacks originally listed here were fully audited on 2026-11-13 — see §7.2.)
9. ~~`UpdateGauge` (`0x600772f4`) consumer~~ **Closed (2026-11-15):** static disassembly and WebHID reference cross-check confirm `UpdateGauge` is dispatched by EP0 OUT `bRequest 0x83` and populates the 2-byte SoC readback buffer (`ctx+0x1d8` at `0x20003848`) queried by EP0 IN `bRequest 0x84` (§7.1).

---

## 10. Credits & pointer material

- X-15 (`github.com/X-15`, issues #1 and #3) — live-USB discovery and readback verification of the EP0 vendor OUT `wLength` overflow and NULL-buffer ITCM DMA (§7.1 addendum), the `0x8b` bulk-arming lead (issue #2), HID Report `0x05` rumble layout, OCOTP fuse-read resolution for `FUN_600d9934` / `FUN_600d995c` via `FUN_00001084` (§7.1.1), `bruce` KVS `0x16` writer audit, and the i.MX RT1060 mask BootROM field-return / CSF `WRITE_DATA` allowlist audit (§4).
- GaryOderNichts — original Stadia Controller flashloader reverse engineering and `stadiatool` (2023, github.com/GaryOderNichts/StadiaController), which first documented the FlexSPI register access path in Google's restricted flashloader.
- lidskialf.net (Andrew de Quincey) — hardware teardown of the Stadia Controller PCB that physically identified the SoC as NXP i.MX RT1061.
- NXP i.MX RT1060 RM (BootROM/HAB chapters), `fsl_flexspi` SDK sources, u-boot `hab.h` — for ROM contract identification.
- NCC Group / fox-it — CVE-2022-45163 research (real vector is the `CHECK_DATA` timing channel).
- ndeadly (`switch2_controller_research`), alexvnesta (`switch2controller`), `playgate-switch2-gateway` — the public Switch 2 BLE host spec.
- nanopb — its `.rodata` error strings are the smoking gun that identified the NVRAM serialization format.
- Community firmware mirror: `luigimannoni.github.io/stadia-controller-flasher` (WebHID), the only working path to the official Bluetooth-mode image since Google's official flasher went dark.

*Document compiled from the complete project record (boot ROM analysis, 4 red-team review cycles, hardware-verified flash primitives, and a full static audit of the application firmware). Extended November 2026 with the gotham cross-image audit (Slot B 235551, shared NOR code library, OTA 282115) and closure of the 0xD2/CSRK and EP0 questions. Corrections and extensions welcome — if you find a real bug in any of these paths, it will be interesting precisely because this reference documents why the obvious ones aren't there.*
