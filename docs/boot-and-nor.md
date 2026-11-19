# Boot Chain, NOR Layout & HABv4 Signature Architecture

[← Back to README](../README.md)

## 1. Firmware layout in NOR (16 MB)

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
