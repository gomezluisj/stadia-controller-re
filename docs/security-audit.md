# Application Firmware & Security Audit

[← Back to README](../README.md)

## 5. Application firmware — codenames and roles

Two stock images shipped; both are still on most units (slot A + slot B):

| Codename | Ver | Role |
|---|---|---|
| **gotham** | 235551 | Wi-Fi-era firmware: Wi-Fi provisioning, Assistant, audio pipeline ("Synapse APM"), fallback gamepad |
| **bruce** | 337784 | The 2023 "Bluetooth mode" image: disables Wi-Fi/jack, pure BLE HID-over-GATT gamepad |

Both are HAB-signed production images. On any unit that received Google's January 2023 Bluetooth-mode update, Slot A holds bruce while Slot B retains the era-Wi-Fi factory image; units "lost" Bluetooth mode only when Slot A was overwritten or invalidated during experiments (the bootloader then falls back to Slot B). Loading bruce is *not* custom firmware — it is the official Google image, and the community flasher (`luigimannoni.github.io/stadia-controller-flasher`, WebHID mirror of the dead stadia.google.com flow) delivers it. Aftermarket note: Bluetooth mode disables the 3.5 mm jack and Wi-Fi permanently (by design of the image, reversible by re-flashing gotham from your own dump).

A **protobuf-over-USB vendor channel** exists in bruce's *app* mode (post-boot, unauthenticated, verb-based) used for provisioning/state — audited in §7.

---

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

---

## 9. What a future researcher still has open

*(Items 1–2 from the original publication — resolving the ATT Signed Write 0xD2/CSRK hardware verdict and the deep audit of gotham — were completed on 2026-11-12; results in §7.2 and §7.4. What remains:)*

1. **The real reading primitive.** CVE-2022-45163 via the actual `CHECK_DATA` DCD timing side channel (NCC Group/fox-it PoC) could yield a slow read path if RT1060 BootROM does not enforce the DCD allowlist on `CHECK_DATA`; testing on hardware and verifying `OCOTP` address admissibility remain open (mostly of research value, since code_exec needs more than a read).
2. **Hardware-class attacks** on HAB: glitching the compare, BEE, SWD (all outside this project's scope).
3. **Custom firmware execution on stock hardware (hardware-verified 2026-11-17..2026-11-18):** while direct cold-boot execution of unsigned NOR images on unmodified fuses remains blocked by BootROM HABv4, **`tchebb/nxp-sdp-overrun` (§4, §10)** provides a USB-only SDP (`1fc9:0135`) path via the 3-byte `sdp_hid_callback` overrun in the NXP RT1060 BootROM — supporting **temporary per-boot execution** (via `ROMC` session mode without altering fuses). Hardware verification on this PVT unit confirmed: (a) in `ROMC` session mode (`hab=0x56787856`), BootROM `SDP READ_REGISTER` still masks `0x00200000` (`0x89232389`) and `0x60000000+` (`4323ccdc7eba4de9`), whereas `SDP WRITE_FILE` + `SDP JUMP_ADDRESS` run unsigned IVT images (`csf=0`) in DTCM/OCRAM; (b) loading standard `MIMXRT1062` `ivt_flashloader.bin` (`82,650 B` @ `0x20208200`) re-enumerates `15a2:0073` (`blhost K2.1.0`), enabling full `16 MiB` NOR preservation dumps and `OCOTP` (`0x401f4400`) inspection; (c) bare-metal DTCM firmware (`stadia-ram-hello`) verified:
   - **Live USB CDC-ACM debug console** on `USB1` (`0x402E0000`) with DMA descriptors/buffers placed in **OCRAM (`0x20200000`)** (required on i.MX RT1060 because `USB1` DMA cannot access DTCM).
   - **TI LP5562** ring LED on `LPI2C2` (`0x30`), **`WM8904`** (`0x1A`) & **`TS3A227E`** (`0x3B`) on `LPI2C1`, **all 17 digital buttons**, **both analog thumbsticks** (`LX/LY` on `ADC1_IN11/12`, `RX/RY` on `ADC1_IN9/10`), and **both `L2`/`R2` Hall-effect triggers** (`ADC1_IN13`/`IN8`, enabled by driving **active-LOW `GPIO2_10 = 0`**; idle `~1734`/`~1747`, full press `~578`/`~616`).
   - **Full Classic Bluetooth HID (`BCM43458F`):** `HCI_Reset`, `228`-packet `.hcd` `patchram` upload, Classic BT discovery as `"Pro Controller"` (`057E:2009`), paginated SDP (`MaxAttributeByteCount` + 2-byte `ContinuationState`), SSP (`Auth=0x04` General Bonding) + encryption (`HCI EVT 08`), `Link Policy` (`0x080F = 0x0005` Role Switch + Sniff Mode), `L2CAP` HID Control/Interrupt (`PSM 0x0011`/`0x0013` with MTU echo), SPI stick calibration (`0x603D`, `0x540` range) & deadzone parameters (`0x6086`/`0x6098`), and **end-to-end validation on both macOS `GameController.framework` and Nintendo Switch 2** (all buttons including `L2`/`R2` triggers + all 4 analog axes).
4. **Unaudited runtime surfaces:** `gotham`'s Wi-Fi-era network stack (Wi-Fi provisioning, TCP/IP, Synapse audio pipeline), runtime parsing across the `BCM43458F` HCI/mailbox boundary (static `BCM43458F` `.hcd` `patchram` and WLAN blobs in both `bruce` and `gotham` were verified inside the HAB-authenticated XIP span via `tools/ivt_csf_inspect.py` in §4.1), and the NXP BootROM mask ROM's internal `hab_rvt` DER/certificate parser (OCOTP/field-return and CSF `WRITE_DATA` allowlisting in the mask ROM were statically audited and closed in §4 / issue #3).
5. ~~NOR hardware capture & `Boot IVT.self` check~~ **Closed (2026-11-15):** surgical hardware dumps captured over `1fc9:0135` → `15a2:0073` (`low_256k.bin`, `bootloader_a_head.bin`, `bootloader_b_head.bin`, `slot_b_head.bin`, `slot_b_ivt_csf.bin`) and analyzed with `tools/nor_slice_inspect.py` / `tools/kvs_parse.py` resolved all open partition/IVT items: (a) `FCB` v1.4.0 (`0x56010400`) on `GigaDevice GD25Q128/GD25LQ128` (`0x17C8`, `USB_ANALOG_DIGPROG = 0x006C0000`), (b) `Boot IVT` (`0x001000`) has **`entry = 0x60801000`** and **`self = 0x60001000`** (closing the `0x60001020` discrepancy), (c) `Bootloader A` (`0x800000`) starts with a matching `0x1000`-byte IVT block while `Bootloader B` (`0x820000`), `id=7`, and `id=10` are completely `0xFF`-erased, (d) `Slot B` (`0x840000`) hosts factory `gotham 235551` (`0x60840000..0x60c20030`), (e) live app-mode Bulk `transfer_bug_report` (`op=9`) and `UnlockChallenge` (`op=1`) succeed pre-unlock (`18d1:9400`), (f) `0x6007014c` was resolved statically as the **USB Host** VID/PID matcher for Tandem secondary-controller input (`0x045e`, `0x054c`, `0x057e`, `0x18d1:0x9400`, `0x28de`), and (g) raw FlexSPI captures of `0x006000..0x03ffff` contain 16-byte **`BEE Region 1` (`AES-128-ECB`, `g = 16`) ciphertext** (`docs/kvs-parser-spec.md` §3.1). Offline CRC-16 validation on plaintext KVS records (`id=9/5/4`) remains applicable only on a CPU-bus (AHB-decrypted) dump or dev-key unit.
6. ~~USB unlock path reconciliation~~ **Closed (2026-11-13; fuse backing resolved 2026-11-15 via issue #3):** §7.1.1 documents the dual-path unlock verified in disassembly — echo-memcmp behind the `(OCOTP fuse 0x26 bit 8 OR IsDfDevice)` gate (the `key_index = 3` / empty-token observation from `docs/kvs-parser-spec.md` §4) alongside the ECDSA P-256 fallback for non-service units. Issue #3 resolved `FUN_600d9934` (`0x26` bit 8) as an on-chip OCOTP silicon fuse read (`FUN_00001084` @ `0x401F4000`, closing the earlier "button combo" sub-item) and confirmed no `bruce` writer exists for KVS key `0x16`.
7. ~~EP0 `issue #1` runtime checks~~ **Verified on hardware (2026-11-15):** static mapping of `bruce` DTCM `.data` (`0x20003670..0x20003fd8` in §7.4) closes the bounded object layout between `ctx` and `uxCriticalNesting` (`0x20003D68`). On hardware, live `EP0 IN` (`0xA1`, `wLength=64`) on 2nd-stage Bootloader `18d1:946b` verified a 64-byte read from ITCM `0x00000000..0x0000003f` (`0xdeaddead` × 8 + `.ramfunc`), while on `18d1:9400`, `EP0 OUT` (`0x21`, `bRequest=0x89`, `wLength=8..9`) mutates volatile RAM state without `STALL` and `EP0 IN` (`0xC1`, `bRequest=0x89`, `wLength=16`) reads `0xdeaddead` ITCM words past the string tail (§7.4). All EP0 state remains volatile in DTCM and cannot persist across reboot.
8. ~~The bootloader's ASN.1/PKCS#7 path was verified only at a coarse level~~ **Closed (2026-11-13):** the bootloader contains no ASN.1 parser at all — all certificate/SRK/signature parsing is delegated to the ROM's HAB `authenticate_image` (`hab_rvt` at `0x0020032c`), and the bootloader-owned surfaces (IVT bounds-check, versioned fixed-size KVS reads, in-place SHA-256, doubly-authenticated update path) were audited function-by-function and found sane (see §4). A bug in the ROM's DER parsing would be an NXP-affecting vulnerability across all HAB-closed RT10xx parts, not a Stadia-specific surface. (The GATT vtable `+0x10` write callbacks originally listed here were fully audited on 2026-11-13 — see §7.2.)
9. ~~`UpdateGauge` (`0x600772f4`) consumer~~ **Closed (2026-11-15):** static disassembly and WebHID reference cross-check confirm `UpdateGauge` is dispatched by EP0 OUT `bRequest 0x83` and populates the 2-byte SoC readback buffer (`ctx+0x1d8` at `0x20003848`) queried by EP0 IN `bRequest 0x84` (§7.1).

---
