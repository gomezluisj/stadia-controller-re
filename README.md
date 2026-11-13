# Stadia Controller — Technical Architecture & Firmware Reference

**Complete reverse-engineering reference for the Google Stadia Controller**
*Compiled November 2026 from static and live analysis of the device (BootROM SDP probing → bootloader → application firmware). Public, partially artifact-backed, with explicit open items documented below. Shared so future researchers don't have to re-derive any of this.*

> **Scope & ethics note.** This document describes defensive architecture and analysis methodology only. No exploit code, no private keys, no vendor-confidential material (everything below was recovered from public firmware images and standard RE tooling). The device is a discontinued product; research like this is how its 16 MB of NOR stays useful after its cloud service went dark in January 2023 and Google's official flasher page followed it.
>
> **TL;DR for the impatient:** the Stadia Controller is an NXP i.MX RT106x (measured MIMXRT1061, Cortex-M7 crossover) + Broadcom BCM43458F BLE radio, with a strongly locked boot chain. BootROM HAB is CLOSED, bootloader enforces RSA-4096 slot verification against a fused SRK hash, and the audited parsers in the application firmware ("bruce", the 2023 Bluetooth-mode image) use nanopb-with-bounds, strnlen-bounded RPC, and descriptor-checked protobuf. Across the statically audited parser corpus (317 restricted flashloader, 547 bootloader, 4,690 application "bruce" functions discovered by Ghidra), we found no memory-corruption bug in bootloader KVS/slots, USB vendor RPC, BLE GATT Prepare/Execute Write, or NVRAM protobuf. However, important scope limits remain: the **NXP BootROM**, the **BCM43458F radio firmware/HCI boundary**, and **gotham's Wi-Fi/audio stack** were not audited; an EP0 control-transfer length bug (issue #1; §7.1 addendum) still lacks hardware PoC testing for bounded/NULL-target writes (§7.4); and several partition-boundary and unlock-path discrepancies noted in §9 remain to be reconciled against raw flash dumps.
>
> The BootROM itself was characterized through its SDP/HAB interfaces and live experiments, not decompiled. The previously open BLE path (ATT Signed Write, 0xD2/CSRK) was closed statically across all three firmware images — CMAC-8 signature verification exists in each (§7.2) — and the gotham audit (§7.4) covered its BLE/ATT, key-store, and NOR persistence layers. Once Bluetooth-mode firmware is loaded, the unit works as a standard generic BLE gamepad on Linux/macOS/Windows/Android.

---

## 1. Hardware inventory (verified)

| Component | Detail |
|---|---|
| SoC | NXP **i.MX RT106x** (Cortex-M7 600 MHz "crossover" MCU). `USB_ANALOG_DIGPROG` (0x400D8260) reads `0x006C0000` (0x6C = RT106x family — the register does not distinguish RT1061/1062/1064; the exact variant MIMXRT1061 comes from PCB silkscreen in public teardowns, lidskialf.net) |
| Serial flash | GigaDevice GD25 "Giga-16m" NOR, 16 MB, XIP-mapped at `0x60000000`, SPI via FlexSPI |
| Bluetooth radio | Broadcom **BCM43458F** (BT 4.2 + BLE). Blob string: `;BCM43458F 37.4MHz Google Gotham BT4.2 [Version: 0054.0161]`. Host loads it via HCI patchram at boot |
| Crypto anchor | HAB (High-Assurance Boot) in mask ROM, RSA-4096/SHA-256; SRK hash fused in OCOTP (not in flash) |
| USB IDs | App mode `18d1:9400` (Google), BootROM SDP `1fc9:0135`, Google flashloader `15a2:0073` |
| BLE identity | Name `StadiaFXXXX-XXXX` (suffix = last 2 bytes of MAC), pure LE (`Flags 0x06` — BR/EDR not supported). Advertising window ≈ 2 min after pairing mode (orange LED blink), then sleeps — re-enter with 4+ s Stadia-button hold |

Serial example referenced throughout: `9C020YCAC6XXXX` (production build; serial masked in this public copy).

### Firmware layout in NOR (16 MB; physical offset vs XIP address — offsets for stadiatool/flash tools, XIP for Ghidra/execution)

| Region | Physical NOR offset | XIP address | Content |
|---|---|---|---|
| FCB | `0x000000–0x000fff` | `0x60000000–0x60000fff` | FlexSPI Configuration Block (LUT at `+0x080`) |
| Boot IVT | `0x001000` | `0x60001000` | Initial IVT + boot data read by the mask ROM (`entry` 0x60800010 → bootloader, no mini stage-1) |
| Slot A | `0x040000–0x13ffff` | `0x60040000–0x6013ffff` | Application image A ("bruce" 337784 after the 2023 BT update) |
| Gap 1 | `0x140000–0x7fffff` | `0x60140000–0x607fffff` | Unallocated / non-executable partitions |
| Bootloader | `0x800000–0x81ffff` | `0x60800000–0x6081ffff` | Google second-stage bootloader (128 KB), own IVT+CSF |
| Slot B | `0x840000–0x93ffff` | `0x60840000–0x6093ffff` | Application image B ("gotham" 235551, factory Wi-Fi-era firmware) |
| Data / KVS | `0x940000–0xffffff` | `0x60940000–0x60ffffff` | KVS, BLE bonds/NVRAM, calibration, provisioning, telemetry buffers, factory pages |

Only the nominal executable slot ranges were assumed signed/verified. **Partition-extent caveat (unreconciled):** measured artifacts and `gotham` analysis extend beyond the nominal 1 MiB bounds above — `bruce_pvt_a_prod_signed.bin` is `1,050,984 B` (`0x100968`, overflowing `0x6013ffff` by `2,408 B`); `gotham OTA 282115` references addresses past `0x60328C34` (> 3 MiB, across `Gap 1`); and `gotham Slot B 235551` calls into a `"NOR-resident shared code library"` (`0x609b2dec..0x60B169A8`, loaded at XIP `0x60800000`, overlapping the `Data / KVS` range above). See §9 item 5: the exact CSF-authenticated bounds of Slot B and that shared code region have not yet been reconciled directly from IVT/CSF tables in a raw full-NOR dump.

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
- OCOTP (fuses) is not readable by software — SRK hash extraction via USB is dead on its own.

With FlexSPI register access, characterized primitives (REV 4.1, all verified against a reference dump with scratch-page canaries):

- **LUT injection:** `configure_memory(9, 0x2000)` copies the FCB lookup table into `FlexSPI->LUT` (sequence: LUTKEY `0x5AF05AF0` → UNLOCK → copy). Living A/B proof: patching 2 bytes of the read sequence changes returned data.
- **Arbitrary NOR read** via IPCMD — caveat: 1 word per transaction (`IDATSZ=4`); the multi-word burst repeats word 0 because the RFDR FIFO doesn't advance on pop.
- **4-byte AHB write** to a virgin page, and **sector erase 4K/64K** — the working incantation is: set `IPCR1[19:16] ISEQID` (not IPCMD!) with `ISEQNUM=0` — the field counts *additional* sequences, so 0 executes exactly 1 — and `IDATSZ=0` for no-data opcodes; then WREN seq 3 → RDSR seq 1 (expect `WEL=0x02`) → SE4K seq 5 / BE64K seq 8 / PP seq 9. LUT indices 0-based: READ=0, RDSR=1, WREN=3, SE4K=5, BE64K=8, PP=9 (matches NXP SDK).

Full repro tooling: GaryOderNichts's `stadiatool` (§10) (`dump_final.py` with resumable dump + canary + auto-recovery `dev.reset()`, `flashloader.py`, `sdp.py`).

---

## 4. Signature & verification architecture

Key facts recovered from decompilation of the bootloader (decompilation corpus not hosted in this repo; addresses in exec space `0x60800000`):

- **App verifier** (`FUN_6080200c`): the app IVT must be exactly at `0x60040000` (region `0x60040000–0x6013ffff`); if `IVT+0x1c` points to a signature table it demands `HAB_SUCCESS = 0xF0` from the ROM using key **`IMG3_1_usr`**. The "unsigned path" only exists if the bootloader's own CSF pointer is 0 — in stock it's `0x60818000` ≠ 0 → dead.
- **Chip status check:** ROM call `0x200324` returns `0xCC`; cross-referencing the i.MX RT1060 RM §9.12.1 and u-boot `hab.h`, that's `REPORT_STATUS` reporting `hab_config` = **closed**, which makes the composite-CSF=0 rejection structural, not accidental.
- **Fingerprinting pre-boot** (`FUN_608027c8`): SHA-256 of each slot against KVS metadata (`AppAMeta/AppBMeta/RecoveryMeta`) using OpenSSL (GothamBIO). Mismatch → slot swap/fallback.
- **Key hierarchy:** SRK3_sha256_4096_65537_v3_ca root (hash in OCOTP fuses, *not* in flash — slot `0x8a0` of NOR is zeros), CSF3_1 / IMG3_1 usr certs, RSA-4096. **Dev- and stage-signed images use different SRKs with revoked indexes in runtime on production units** — physically verified: flashing a dev- or stage-signed image to slot A → rejected, clean fallback to slot B.
- Bootloader update path supports verified install + rollback; no skip-verification branch exists.
- **Bootloader-side ASN.1/PKCS#7 audit (2026-11-13): there is no ASN.1 parser in the bootloader.** The verification vtable entries (`DAT_60801fa0/0x60801fa4/0x60801fa8`) resolve to `0x00200304` (report status), `0x0020032c` (`authenticate_image`), and `0x00200308` (close) — the i.MX RT1060's ROM-resident `hab_rvt`. All certificate/SRK/signature DER parsing happens inside the NXP mask ROM; the bootloader's own contribution is (1) the IVT bounds-check `FUN_60801fac` (validates all 255 pointer entries against the image range before invoking HAB), (2) versioned fixed-size KVS metadata reads (`FUN_6080cbf4` — BookkeepVer requires exactly version 8 / size 0x20; BookkeepMeta reads 2 bytes behind a size check), (3) an in-place SHA-256 block transform (`FUN_6080ce00`) used for slot fingerprinting, and (4) the update path `FUN_60801dd4`, which authenticates **both** the incoming and the currently-installed bootloader IVT via the ROM before installing ("New bootloader failed image auth" aborts without touching flash). All bootloader-owned parsing surfaces verified sane.

**Consequence (assuming intact NXP mask ROM HABv4): cold-boot execution of unsigned code has no known software path.** Writing arbitrary flash outside active verification was never the hard part (see §3) — getting it *executed* is.

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

Dispatcher `FUN_60077362` — dispatches by **verb** (`param_2`, 0x0–0xd), not by payload opcode:

| Verb | Action | Copy bound |
|---|---|---|
| 0 | no pointer set (declared length 0) | — |
| 1/2/3/4/5 | return pointers into context (1 → +0x190, 2 → +0x64, 3 → +0x12C, 4 → +0x1d8, 5 → +0xC8) | fixed sizes (8/8/8/2/1 bytes) |
| 6 | **Shipping-mode entry** (factory flow): fetches the runtime power-manager handle (`DAT_6005bdb0` → OCRAM global `0x2000d218`) and issues a system-service call via the app's syscall jump table (ITCM thunk `0x6013d398` → `0x1835`) — the same call shape as the `"FROM_USB_VENDOR" / "Entering shipping mode from USB Vendor"` log path (sibling handler logs `"Disabling charging from USB Vendor"`). It is a state transition into the vendor power manager for shipping/long-storage mode, **not** a reboot into SDP/flashloader | — |
| 7 | refresh `ctx+0x1a0` from its backing store, then return it | copy/measure `strnlen`-bounded at 0x25 |
| 8, 9 | return pointers to `ctx+0x1c5 / +0x1d1` (no copy) | `strnlen`-bounded (0xc / 7 bytes), reject `len ≥ max` |
| 0xa | binary lookup in 6-entry table `{opcode u32, char* name}` @ `0x6010a0dc` (provisioning states: `MissingProvisioningData`, `NeedsFdr`, `FailedToReadFuses`, `ReadyFor{Developer,InternalUser,End}Use`) | copy caps at 0x3f |
| 0xb, 0xc | state getters | no copy |
| default | logs `"Invalid vendor RPC request: "` | — |

Every length check is `strnlen`-style (`FUN_600db002` is literally a bounded strlen) with explicit upper bound rejection. **No overflow.** Scope note: this is a **static audit** of the decompiled dispatcher; in the live unit the unauthenticated USB vendor endpoint is a factory/provisioning channel whose bulk interface does not arm by default in normal user operation (the arming precondition — an EP0 `0xA1 0x8b` class IN — was demonstrated on 2026-11-13, issue #2). Note for researchers: the dispatcher's "invalid opcode" log is a live oracle — unknown verbs produce identifiable log output, making fuzzing measurable (we just found nothing to fuzz into).  

**Addendum (2026-11, issue #1): the EP0 control path into this dispatcher is not covered by the audit above.** The USB setup handler (FUN_60054dc0) dispatches class and vendor control requests to the same dispatcher, then runs the OUT data stage with the host's wLength as the receive length, without comparing it to the length the dispatcher declared for the request. Consequences, confirmed statically on bruce and on gotham 235551 (twin handler at 0x60076e5c, byte-identical sequence): (a) an OUT transfer on a read-mapped bRequest (e.g. 0x81, declared length 8 at ctx+0x190) writes as many bytes as the host sends, across the adjacent context fields, and the serial field at ctx+0x1c5 sits 0x35 bytes into that range; (b) dispatcher cases that return success without setting a buffer (0x80, 0x82, 0x83, 0x85, 0x86) leave the request buffer NULL, so an OUT data stage receives at address 0. The per-case bounds in the table above describe the dispatcher's own copies and are unaffected; the bug is in the setup handler's data stage, which this audit had not covered. Hardware demonstration by the reporter (issue #1); maintainer verification is static, with reproduction PoCs written from the code paths but not yet run on a maintainer unit.

#### 7.1.1 Bulk vendor channel: message schema, command table, and the unlock gate (2026-11-13, live-verified)

The bulk interface is a separate protocol above the EP0 verbs, served by the `vendor_usb_task` (strings cluster `0x60124528+`, streaming nanopb decoder with its own error strings). The request message is protobuf: **outer field 1 = request id** (echoed in the response, any u32 varint), **outer field 2 = a nested message** whose fields land in a request struct as **kind** (`+8`, u32) and **op** (`+0x10`, u8), with a length-prefixed bytes field at `+0x14/+0x18` (token submission). Three kinds exist (inner field 1):

| kind | Meaning |
|---|---|
| 2 | **unlock token submission** — see gate below |
| 3 | **RPC** — dispatched through a 16-entry provider table at `0x6010a174`; **op 1 = unlock-challenge generation** (string built at `ctx+0x1380` from the UUID string at OCRAM `0x2000d1d5` — the same value EP0 verb 7 exposes — plus a hex-formatted runtime counter, then stored at `ctx+0x135c`); other ops = provider calls |

A request with inner kind 1 is **not handled** (logged and dropped — the "unlock challenge request" is RPC kind 3/op 1, not a separate kind; an earlier revision of this section mislabeled it). Unknown kinds produce a generic error-3 response; a simple request (no nested message) logs `"Ignoring simple request that is not an 'unlock challenge'"`. The 16 providers, recovered by disassembling each entry's type/op match: device-data getter (type 3/op 4 — returns the firmware build number and runtime state), KVS get/set (`Failed to read value` / `Failed to set value:`), power state control (type 4, ops get/discharge/charge — `"Unknown power state: "`), bug-report transfer/clear (`transfer_bug_report.cc`, type 3/ops 2,7,8,9,0xa and type 5), **firmware upload (type 6** — `firmware_image_upload.cc` + `http_flash_writer.h`, CRC-checked, partition-bounds-checked flash writer), and the shipping-mode path.

**The unlock gate — dual-path (reconciled 2026-11-13, closing the red-team flag in `docs/kvs-parser-spec.md` §4 / §9 item 6).** Every provider call passes a permission check (`FUN_60077948`): the request's required mask must be a subset of an allow-mask at `ctx+0x113c`, populated at boot by the provisioning flow (`FUN_600a3f40`; on this ReadyForEndUserUse unit it is `0x600c5c21`). Locked requests log `"Device locked for "` (rate-limited to once per 60 s). Kind 2 (token submission) has **two verification paths, selected by `FUN_600d7cdc`** (disasm `0x60077d92`):

- **Echo path (factory/service):** the gate passes if **either** the companion-chip button state indicates the physical service combo (`FUN_600d9934` — register `0x26`, bit 8 **inverted**) **or** the unit is factory-provisioned (`FUN_600d72ec(0x16,…)` = `IsDfDevice`, KVS-backed). Gate pass → the token is accepted by a plain **echo compare**: same length as the challenge (`strlen` at OCRAM `0x2000d1d5`) and `memcmp(token, challenge)` equality → **mask set to `0xFFFFFFFF` directly, no cryptography** (branch `0x60077da2–0x60077db0` → `0x60077e9e`). This reconciles the earlier triage observation of a `"successful empty-token unlock"` on `key_index = 3` (`A OR B` gate, echo memcmp against `SsdpUdn`): an unseeded/empty challenge plus an empty token is a trivially equal echo pair. The exact physical button combo behind register `0x26` bit 8 was not mapped in this session.
- **ECDSA path (remote/factory-signed):** if the gate fails (end-user unit, no combo held), kind 2 falls through to `0x60077db2`: SHA-256 over the challenge, **ECDSA P-256 verification against an embedded Google public key** (two PEM `MFkwE…` blobs at `0x60124756`/`0x60124809`; strings `"Failed to configure public key bio"`, `"Failed to load public key"`, `"EC verification failed."`). Success → same mask `0xFFFFFFFF`.

On success the full provider table — including the firmware upload writer — becomes callable. **Live-verified 2026-11-13 (PoC `bulk_unlock_echo2.py`):** on this ReadyForEndUserUse unit the unlock is unreachable through a **double lock**: (1) challenge generation (RPC kind 3/op 1) itself passes through the same permission gate with a required mask of `0x3e8`, which `0x600c5c21` does not contain — the request times out (the task logs `"Device locked for "` and never responds), so no challenge is ever stored at `ctx+0x135c`; and (2) kind 2 without a pending challenge returns a clean status-4 rejection (`ctx+0x135c == NULL`) before any token verification — neither the echo nor the ECDSA path is reachable. Note also that challenge generation computes a **key_index** (`ctx+0x1422`: `3` = service-combo/DF gate passed → echo token; `1`/`2` = power-state-dependent ECDSA variants) *before* the mask gate, which is the origin of the historical `key_index = 3` / empty-token observation — it was recorded on a unit whose provisioning state (or held combo) passed that gate. **Security consequence, corrected:** the bulk channel is *not* gated by Google's EC key alone; on service units it opens by **(physical possession: service combo or DF unit) AND (echoing the challenge back)** — a deliberate factory flow. On this end-user unit it is closed by the provisioning mask before any cryptography is even consulted: even Google's ECDSA private key could not complete an unlock here without first flipping the provisioning state. **But the terminal gate for custom firmware is unchanged:** even fully unlocked, `firmware_image_upload` only writes flash; cold-boot execution still requires passing BootROM/bootloader HAB RSA-4096 verification.

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

**EP0 vendor OUT length bug (bruce, live USB): multi-KB OCRAM escalation blocked; bounded and NULL-target cases unclosed.** Static analysis of the oversized OCRAM write identifies two kill mechanisms before any multi-tens-of-KB overwrite reaches the power-manager handle (`0x2000D218`): (1) an IRQ-nesting critical-section counter at `0x20003D68` (offset 0x568) — the enter/exit pair (`FUN_60048580`/`FUN_600485c8`, panic path `FUN_600cc5ac`) manages `BASEPRI` IRQ masking and panics/hangs if corrupted; and (2) a live-USB-state window at `0x20003F40–0x20003F5F` consumed by `FUN_60060fe8` / `FUN_6013d4d8`. **Open gaps in that argument (§9 item 7):** (a) the base address of `ctx` and all objects between `ctx+0x190` and `0x20003D68` were not mapped to rule out short bounded writes; and (b) Case (b) from the §7.1 addendum (`0x80, 0x82, 0x83, 0x85, 0x86` leaving the receive buffer `NULL`, writing at address `0x00000000` in Cortex-M7 ITCM space) has not been checked against MPU/DMA behavior or tested on maintainer hardware. Architecturally, any EP0 path remains volatile and USB-tethered — it cannot persist across cold boot because HAB re-authenticates flash.

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
| `tools/udev/99-stadia-controller.rules` | Linux udev permissions for App (`18d1:9400`), SDP (`1fc9:0135`), and Flashloader (`15a2:0073`) modes |
| `ghidra/DecompAll.java`, `DecompForce.java`, `Xrefs.java` | Headless Ghidra scripts to reproduce bulk decompilation and xref queries on your own dumps |
| `evidence/` | Full reference SHA-256 hashes (`SHA256SUMS.txt` for slot/bootloader/flashloader artifacts — no KVS/full-16MB NOR dump yet), abridged FlexSPI erase summary (`flexspi_erase_verify.log`), and BLE input log (`ble_bruce_input.log`) |

### External tools & reference hashes (not hosted)

Copyrighted firmware binaries and full decompilation corpora are excluded via `.gitignore`. To reproduce locally from your own hardware, use GaryOderNichts's `stadiatool` (sdp/flashloader/dump with canary + auto-recovery) plus the FlexSPI primitives in §3, then run `analyzeHeadless` with `-processor ARM:LE:32:v8T -loader BinaryLoader -loader-baseAddr <addr>` and the scripts in `ghidra/`:

- `bootloader_dump.bin`: 131,072 B (sha256 `59ebfd2c…f2ca0`), base `0x60800000`, 547 functions
- `restricted_ivt_flashloader.bin`: 100,672 B, base `0x20002400`, 317 functions
- `bruce_pvt_a_prod_signed.bin` (build 337784): 1,050,984 B, base `0x60040000`, 4,690 functions
- Additional corpora for reproducing the gotham audit: the OTA 282115 stable image (sha256 `269bb21160ea6d1366e71bb9c9b148e2782ea967b81c7b6ff038e7d49b61e00f`, XIP base `0x60040000`), the Slot B 235551 application (read from NOR offset `0x840000` of your own dump), and the shared NOR code library (XIP base `0x60800000`)
- **Provenance warning:** the artifact circulating as `gotham235551.elf` is **not** build 235551 — it is an ELF32 wrapper (single `LOAD` at `0x60040000`) whose file offset `0x1000` embeds a payload byte-identical to the OTA 282115 stable image (sha256 above). Rename it accordingly before using it in analysis; the actual 235551 image only exists in the Slot B region of a hardware dump.

Also hashed in `evidence/SHA256SUMS.txt`: `bruce_dvt_a_dev_signed.bin` (the dev-signed build 337784 image whose rejection on production units is described in §4), `gotham235551.elf` and `flash_head.bin`.

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
4. **Unaudited runtime surfaces:** `gotham`'s Wi-Fi-era network stack (Wi-Fi provisioning, TCP/IP, Synapse audio pipeline), the `BCM43458F` BLE/Wi-Fi `patchram` firmware and HCI/mailbox boundary, and the NXP BootROM mask ROM (`hab_rvt` DER/CSF parser).
5. **NOR partition & Boot IVT reconciliation:** capture the first real KVS dump for `tools/kvs_parse.py`, verify the `Boot IVT.self` field (`0x60001020` vs expected `0x60001000`) directly from raw `flash_head.bin` bytes, and reconcile the actual CSF-authenticated bounds of `bruce` (`1,050,984 B`), `gotham OTA 282115` (`0x60328C34`+), and the `0x60800000..0x60B169A8+` code mapped inside nominal `Data / KVS` (`§1` vs `§7.4`).
6. ~~USB unlock path reconciliation~~ **Closed (2026-11-13):** §7.1.1 now documents the dual-path unlock verified in disassembly — echo-memcmp behind the `(reg 0x26 bit-8-inverted OR IsDfDevice)` gate (the `key_index = 3` / empty-token observation from `docs/kvs-parser-spec.md` §4) alongside the ECDSA P-256 fallback for non-service units. Remaining minor sub-item: the exact physical button combo behind companion-chip register `0x26` bit 8 was not mapped.
7. **EP0 `issue #1` residual checks:** test PoCs on maintainer hardware for bounded OCRAM writes below `0x20003D68` (`ctx` layout) and Case (b) `NULL` / address-`0` (ITCM) behavior.
8. ~~The bootloader's ASN.1/PKCS#7 path was verified only at a coarse level~~ **Closed (2026-11-13):** the bootloader contains no ASN.1 parser at all — all certificate/SRK/signature parsing is delegated to the ROM's HAB `authenticate_image` (`hab_rvt` at `0x0020032c`), and the bootloader-owned surfaces (IVT bounds-check, versioned fixed-size KVS reads, in-place SHA-256, doubly-authenticated update path) were audited function-by-function and found sane (see §4). A bug in the ROM's DER parsing would be an NXP-affecting vulnerability across all HAB-closed RT10xx parts, not a Stadia-specific surface. (The GATT vtable `+0x10` write callbacks originally listed here were fully audited on 2026-11-13 — see §7.2.)

---

## 10. Credits & pointer material

- GaryOderNichts — original Stadia Controller flashloader reverse engineering and `stadiatool` (2023, github.com/GaryOderNichts/StadiaController), which first documented the FlexSPI register access path in Google's restricted flashloader.
- lidskialf.net (Andrew de Quincey) — hardware teardown of the Stadia Controller PCB that physically identified the SoC as NXP i.MX RT1061.
- NXP i.MX RT1060 RM (BootROM/HAB chapters), `fsl_flexspi` SDK sources, u-boot `hab.h` — for ROM contract identification.
- NCC Group / fox-it — CVE-2022-45163 research (real vector is the `CHECK_DATA` timing channel).
- ndeadly (`switch2_controller_research`), alexvnesta (`switch2controller`), `playgate-switch2-gateway` — the public Switch 2 BLE host spec.
- nanopb — its `.rodata` error strings are the smoking gun that identified the NVRAM serialization format.
- Community firmware mirror: `luigimannoni.github.io/stadia-controller-flasher` (WebHID), the only working path to the official Bluetooth-mode image since Google's official flasher went dark.

*Document compiled from the complete project record (boot ROM analysis, 4 red-team review cycles, hardware-verified flash primitives, and a full static audit of the application firmware). Extended November 2026 with the gotham cross-image audit (Slot B 235551, shared NOR code library, OTA 282115) and closure of the 0xD2/CSRK and EP0 questions. Corrections and extensions welcome — if you find a real bug in any of these paths, it will be interesting precisely because this reference documents why the obvious ones aren't there.*
