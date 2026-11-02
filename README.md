# Stadia Controller — Technical Architecture & Firmware Reference

**Complete reverse-engineering reference for the Google Stadia Controller**
*Compiled November 2026 from a full security audit of the device (BootROM → bootloader → application firmware). Public, artifact-backed, and reproducible. Shared so future researchers don't have to re-derive any of this.*

> **Scope & ethics note.** This document describes defensive architecture and analysis methodology only. No exploit code, no private keys, no vendor-confidential material (everything below was recovered from public firmware images and standard RE tooling). The device is a discontinued product; research like this is how its 16 MB of NOR stays useful after its cloud service (and Google's official flasher) went dark in January 2026.
>
> **TL;DR for the impatient:** the Stadia Controller is an NXP i.MX RT106x (measured MIMXRT1061, Cortex-M7 crossover) + Broadcom BCM43458F BLE radio, with an unusually well-hardened firmware chain. BootROM HAB is CLOSED, bootloader enforces RSA-4096 slot verification against a fused SRK hash, and the application firmware ("bruce", the 2023 Bluetooth-mode image) uses nanopb-with-bounds, strnlen-bounded RPC, and descriptor-checked protobuf throughout. We audited 5,554 decompiled functions in total (317 restricted flashloader, 547 bootloader, 4,690 application "bruce") and found no memory-corruption bug in the statically audited parsers (bootloader KVS/slots, USB vendor RPC, BLE GATT Prepare/Execute Write, NVRAM protobuf). The BootROM itself was characterized through its SDP/HAB interfaces and live experiments, not decompiled. One live BLE path (ATT Signed Write, 0xD2/CSRK, under gotham) remains an **open hardware verdict** (§7.2, §9). It is, however, a first-class generic BLE gamepad on Linux/macOS/Windows/Android once the Bluetooth-mode firmware is loaded.

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

Only the executable slot ranges are signed/verified. Everything else (KVS, NVRAM, calibration) **is not covered by HAB** — see §7 for the audit result of eating from those regions anyway.

---

## 2. Boot chain

```
Mask ROM (HAB4.1)                                  — NXP code, non-updatable
  → reads the fixed IVT at 0x60001000 (flash offset 0x1000), byte-exact:
    header    0x412000D1
    entry     0x60800010   ← direct pointer into the Google bootloader — no mini stage-1
    dcd       0x00000000
    boot_data 0x60001020 (start 0x60000000, length 0x01000000 = whole 16 MB XIP space)
    self      0x60001020
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

- **Whitelisted** memory access: USB PHY ID register (`0x400D8260`) and the **FlexSPI register window `0x402A8000+`**. That FlexSPI window is the load-bearing hole: it allows driving the SPI engine directly, which is how full NOR dumps and flash erase/write were performed.
- **Whitelist-rejected** (`0x27d8`): writes to RAM, OCOTP shadow, OCRAM, DTCM/ITCM, XIP space, ROM.
- **Compiled out** (`0x2710` = disabled): `FlashReadResource`, `Call`, `Execute`.
- OCOTP (fuses) is not readable by software — SRK hash extraction via USB is dead on its own.

With FlexSPI register access, characterized primitives (REV 4.1, all verified against a reference dump with scratch-page canaries):

- **LUT injection:** `configure_memory(9, 0x2000)` copies the FCB lookup table into `FlexSPI->LUT` (sequence: LUTKEY `0x5AF05AF0` → UNLOCK → copy). Living A/B proof: patching 2 bytes of the read sequence changes returned data.
- **Arbitrary NOR read** via IPCMD — caveat: 1 word per transaction (`IDATSZ=4`); the multi-word burst repeats word 0 because the RFDR FIFO doesn't advance on pop.
- **4-byte AHB write** to a virgin page, and **sector erase 4K/64K** — the working incantation is: set `IPCR1[19:16] ISEQID` (not IPCMD!) with `ISEQNUM=0` — the field counts *additional* sequences, so 0 executes exactly 1 — and `IDATSZ=0` for no-data opcodes; then WREN seq 3 → RDSR seq 1 (expect `WEL=0x02`) → SE4K seq 5 / BE64K seq 8 / PP seq 9. LUT indices 0-based: READ=0, RDSR=1, WREN=3, SE4K=5, BE64K=8, PP=9 (matches NXP SDK).

Full repro tooling: `stadiatool` (`dump_final.py` with resumable dump + canary + auto-recovery `dev.reset()`, `flashloader.py`, `sdp.py`).

---

## 4. Signature & verification architecture

Key facts recovered from decompilation of the bootloader (`~/ghidra_work/decomp_all.c`, addresses in exec space `0x60800000`):

- **App verifier** (`FUN_6080200c`): the app IVT must be exactly at `0x60040000` (region `0x60040000–0x6013ffff`); if `IVT+0x1c` points to a signature table it demands `HAB_SUCCESS = 0xF0` from the ROM using key **`IMG3_1_usr`**. The "unsigned path" only exists if the bootloader's own CSF pointer is 0 — in stock it's `0x60818000` ≠ 0 → dead.
- **Chip status check:** ROM call `0x200324` returns `0xCC`; cross-referencing the i.MX RT1060 RM §9.12.1 and u-boot `hab.h`, that's `REPORT_STATUS` reporting `hab_config` = **closed**, which makes the composite-CSF=0 rejection structural, not accidental.
- **Fingerprinting pre-boot** (`FUN_608027c8`): SHA-256 of each slot against KVS metadata (`AppAMeta/AppBMeta/RecoveryMeta`) using OpenSSL (GothamBIO). Mismatch → slot swap/fallback.
- **Key hierarchy:** SRK3_sha256_4096_65537_v3_ca root (hash in OCOTP fuses, *not* in flash — slot `0x8a0` of NOR is zeros), CSF3_1 / IMG3_1 usr certs, RSA-4096. **Dev- and stage-signed images use different SRKs with revoked indexes in runtime on production units** — physically verified: flashing a dev- or stage-signed image to slot A → rejected, clean fallback to slot B.
- Bootloader update path supports verified install + rollback; no skip-verification branch exists.

**Consequence: cold-boot execution of any unsigned code is not reachable by software.** Writing arbitrary flash was never the hard part (see §3) — getting it *executed* is.

### CVE applicability (checked, not assumed)

| CVE | Verdict on RT1060 |
|---|---|
| CVE-2022-45163 (SDP info leak) | **Applies in class** (corrected assessment): the project's initial test of `READ_REGISTER` returned synthetic constants and early logs closed this CVE on that basis; red-team review corrected it — the actual vector is a *timing side channel in `CHECK_DATA` within DCD* (NCC Group/Fox-IT), not `READ_REGISTER`. That PoC remains untested on this unit and would yield a slow read primitive for OCOTP/fuses — research leverage, not code-exec. |
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

**With bruce, input flows:** verified end-to-end on Linux — the unit enumerates as `/dev/input/js0` (`StadiaXXXX-XXXX`), sticks/buttons/triggers produce continuous events over 60+ reads in 20 s. *Earlier claims of "no input reports" were an artifact of testing under gotham (the Wi-Fi-era fallback), not bruce.* If you inherited an unresponsive unit, check which image is actually running in slot A.

---

## 7. Security audit of the application firmware (audited paths & open questions)

Method: Ghidra 12.2 headless, `ARM:LE:32:v8T`, BinaryLoader at `0x60040000`; full decompilation to ~169k lines / 4,690 functions. Heuristic scan for stack arrays indexed by unbounded variables, then manual review of top candidates. Reference implementations of the audit scripts can be reconstructed trivially (search, rank by `varIdx` count, read the top N).

### 7.1 USB vendor RPC (static audit)

Note: this section documents static analysis of the decompiled handler. On live hardware running bruce, the USB bulk vendor interface did not arm by default during runtime testing.

Dispatcher `FUN_60077362` — dispatches by **verb** (`param_2`, 0x0–0xd), not by payload opcode:

| Verb | Action | Copy bound |
|---|---|---|
| 0/1/2/3/4/5 | return pointers into context (+0x64/+0xC8/+0x12C/+400/+0x1d8) | fixed sizes |
| 6 | **Shipping-mode entry** (factory flow): fetches the runtime power-manager handle (`DAT_6005bdb0` → OCRAM global `0x2000d218`) and issues a system-service call via the app's syscall jump table (ITCM thunk `0x6013d398` → `0x1835`) — the same call shape as the `"FROM_USB_VENDOR" / "Entering shipping mode from USB Vendor"` log path (sibling handler logs `"Disabling charging from USB Vendor"`). It is a state transition into the vendor power manager for shipping/long-storage mode, **not** a reboot into SDP/flashloader | — |
| 7, 8, 9 | copy into `ctx+0x1a0 / +0x1c5 / +0x1d1` | `strnlen`-bounded (0x25 / 0xc / 7 bytes), reject `len ≥ max` |
| 0xa | binary lookup in 6-entry table `{opcode u32, char* name}` @ `0x6010a0dc` (provisioning states: `MissingProvisioningData`, `NeedsFdr`, `FailedToReadFuses`, `ReadyFor{Developer,InternalUser,End}Use`) | copy caps at 0x3f |
| 0xb, 0xc | state getters | no copy |
| default | logs `"Invalid vendor RPC request: "` | — |

Every length check is `strnlen`-style (`FUN_600db002` is literally a bounded strlen) with explicit upper bound rejection. **No overflow.** Scope note: this is a **static audit** of the decompiled dispatcher; in the live unit the unauthenticated USB vendor endpoint is a factory/provisioning channel that is not armed by default in normal user operation. Note for researchers: the dispatcher's "invalid opcode" log is a live oracle — unknown verbs produce identifiable log output, making fuzzing measurable (we just found nothing to fuzz into).

### 7.2 BLE GATT write paths (Prepare/Execute closed statically; Signed Write open in hardware)

- Prepare Write `FUN_60069160`: reassembly buffer at `ctx+0x1ac0` (0x259 bytes), check `offset + len < 0x259` with both operands `uint` and `len` bounded by MTU — **correct**.
- Execute Write `FUN_60069b20` → `FUN_6006ad00`: the Prepare-Write **value_offset is never persisted** (only handle @0x1abc and accumulated length @0x1abe) — the classic two-phase offset-overflow trap is dead by design.
- Residual: attribute write callbacks via vtable `+0x10` receive up to 0x259 bytes; per-attribute destination buffers were not exhaustively audited.

Scope note: this static closure covers **Prepare/Execute Write (ATT opcodes 0x16/0x18)** in FUN_60069160/FUN_60069b20. A separate live experiment against **ATT Signed Write (opcode 0xD2 with CSRK)** was performed under the gotham image with an ambiguous hardware result and was not conclusively closed; it remains the top open runtime question (§9). Closing it statically for bruce would mean auditing the 0xD2 handler in `bruce_decomp.c`.

### 7.3 Untrusted NOR → boot-time parsers (the "interesting" one)

Since HAB only covers executable slots, and we have arbitrary NOR erase/write via the flashloader (§3), anything bruce reads from untrusted NOR at every cold boot is attacker-controlled. This is the only path that would be both untethered and pre-auth. Audited consumers:

1. **Bluetooth bonds/NVRAM parser** (`FUN_60082814` + wire-format layer `FUN_600dfxxx`): this is built on **nanopb with bounds checks compiled in** — evidence: `.rodata` error strings `"array overflow"`, `"bytes overflow"`, `"stream full"`, `"callback failed"` are present (they only emit with bounds-check builds of nanopb). Array entries validated against descriptor `max_count` per-write; all wire reads go through a stream object bounded by `bytes_left`; the NVRAM iterator (`FUN_600dfadc`/`df918`) derives its limits from the **caller's buffer**, never from flash-record headers; page-walk validates tags before advancing.
2. **Stick/trigger calibration** (`FUN_60043834/43ecc/43988`): operates on `std::vector<float>` begin/end (the vector carries its own size from the protobuf), never a fixed array with an assumed count. A lying count only inflates a heap allocation (DoS, not controllable overflow).
3. **KVS typed setters/getters** (`FUN_60066b40/66c28/66ce0`): per-type setters (`FUN_600d71xx`) + capability flag check + invalid-type rejection. No raw `memcpy` of payload into fixed buffers.

**Verdict: no exploitable path from untrusted NOR either.** The consistent defensive pattern across five independent subsystems (HAB, bootloader KVS, vendor RPC, GATT, NVRAM/calibration) strongly suggests systematic internal security review at Google plus a house style of nanopb-with-bounds and capped containers. We're calling this one closed unless/until someone publishes a concrete bug.

### 7.4 What this does *not* close

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

### External tools & reference hashes (not hosted)

Copyrighted firmware binaries and full decompilation corpora are excluded via `.gitignore`. To reproduce locally from your own hardware, use GaryOderNichts's `stadiatool` (sdp/flashloader/dump with canary + auto-recovery) plus the FlexSPI primitives in §3, then run `analyzeHeadless` with `-processor ARM:LE:32:v8T -loader BinaryLoader -loader-baseAddr <addr>` and the scripts in `ghidra/`:

- `bootloader_dump.bin`: 131,072 B (sha256 `59ebfd2c…f2ca0`), base `0x60800000`, 547 functions
- `restricted_ivt_flashloader.bin`: 100,672 B, base `0x20002400`, 317 functions
- `bruce_pvt_a_prod_signed.bin` (build 337784): 1,050,984 B, base `0x60040000`, 4,690 functions

**Methodological lessons (worth more than the addresses):**
1. **Verify primitives with raw captures.** Both the SDP tool and BlueZ lied to us at least once each — parser-level output masked what the wire actually carried. btmon/raw-HID under any parser is the only trustworthy ground truth.
2. **Close by layers, not in block.** The first REV of our notes declared "impossible by design" from partial evidence; three red-team reviews each found an untested assumption (wrong CVE vector, wrong firmware under test, unverified gating claim). Every architectural verdict needs each link measured.
3. **Label every claim demonstrated / probable / not-demonstrated.** The single cheapest technique that caught the most errors.
4. **Recovery before aggression.** With the 10-second SDP recovery validated on day 1, every experiment became cheap to attempt.
5. **A BLE "won't connect" usually isn't the device.** Fresh bond + registered agent + in-window connection solves ~90% of stock-firmware pairing failures on Linux.

---

## 9. What a future researcher still has open

1. **Resolving the ATT Signed Write (0xD2 / CSRK) hardware verdict.** Re-run the signed-write test under controlled instrumentation, comparing the 0xD2 opcode handler between gotham and bruce, to determine whether the ambiguous live result observed under gotham corresponds to a reachable corruption primitive.
2. **Deep audit of gotham (Slot B, build 235551).** Because gotham is a valid Google-signed image that runs automatically on any Slot A fallback — and includes the full legacy Wi-Fi + network provisioning stack removed in bruce — it represents a larger and less-audited runtime attack surface than bruce. Assuming it shares bruce's clean bill of health without an equivalent function-by-function audit would be premature.
3. **The real reading primitive.** CVE-2022-45163 via the actual `CHECK_DATA` DCD timing side channel (NCC Group/fox-it PoC) would give a slow read path for OCOTP/fuses — mostly of research value, since code_exec needs more than a read.
3. **Hardware-class attacks** on HAB: glitching the compare, BEE, SWD (all outside this project's scope).
3. **Switch 2 protocol emulation** on the radio itself requires speaking Nintendo's proprietary BLE from the controller's own BT chip — not reachable with signed stock firmware; would need either a custom image (HAB blocks) or a hardware transplant. The beacon/wake spec is however fully documented publicly (ndeadly, alexvnesta) and reproducible from any other BLE-capable device you control.
4. **Gotham's Wi-Fi subsystem** was not audited to the same depth as bruce (pattern of defensive style suggests closure, but it's declared rather than measured).
5. **The bootloader's ASN.1/PKCS#7 path** and the individual GATT vtable `+0x10` write callbacks were verified only at a coarse level — candidates if anyone wants more leaves to turn over.

---

## 10. Credits & pointer material

- GaryOderNichts — original Stadia Controller flashloader reverse engineering and `stadiatool` (2023, github.com/GaryOderNichts/StadiaController), which first documented the FlexSPI register access path in Google's restricted flashloader.
- lidskialf.net (Andrew de Quincey) — hardware teardown of the Stadia Controller PCB that physically identified the SoC as NXP i.MX RT1061.
- NXP i.MX RT1060 RM (BootROM/HAB chapters), `fsl_flexspi` SDK sources, u-boot `hab.h` — for ROM contract identification.
- NCC Group / fox-it — CVE-2022-45163 research (real vector is the `CHECK_DATA` timing channel).
- ndeadly (`switch2_controller_research`), alexvnesta (`switch2controller`), `playgate-switch2-gateway` — the public Switch 2 BLE host spec.
- nanopb — its `.rodata` error strings are the smoking gun that identified the NVRAM serialization format.
- Community firmware mirror: `luigimannoni.github.io/stadia-controller-flasher` (WebHID), the only working path to the official Bluetooth-mode image since January 2026.

*Document compiled from the complete project record (boot ROM analysis, 4 red-team review cycles, hardware-verified flash primitives, and a full static audit of the application firmware). Corrections and extensions welcome — if you find a real bug in any of these paths, it will be interesting precisely because this reference documents why the obvious ones aren't there.*