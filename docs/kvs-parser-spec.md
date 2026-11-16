# KVS parser spec — Stadia `key_value_store.cc` NOR dumps

Deliverable: `kvs_parse.py` (stdlib only) + this spec. Purpose: when a future
hardware session produces raw NOR region dumps, the KVS is fully analyzable
offline — no further reverse engineering needed.

Conventions: **FACT** = backed by cited code/bytes or by a run recorded here.
**INFERENCE** = labeled deduction. Addresses are gotham OTA 282115 (linked at
`0x60040000`, mislabeled `gotham 235551` in early drafts; see `README.md` §8)
unless marked bruce (also based at `0x60040000`; on-NOR Slot B 235551 starts at
`0x60840000`).

## 1. Format as implemented

### Sector header (`2 * align(8)` bytes: 16 B when `g <= 8`, 32 B when `g = 16`) — FACT (`gotham FUN_6020415E`, `bruce Mount 0x600cb6fc`)
- **Chunk 0 (`+0x00 .. +align(8)-1`, `16 B` on BEE partitions with `g = 16`):**
  - `+0x00` u16 magic `0xABCD`; `+0x02` u16 version, accepted `2..4`.
  - `+0x04` u16 **granularity `g`** (verified at `0x600cb89c` in `bruce Mount`: when `version == 2`, firmware forces `sector_g = 1`; when `version in (3, 4)`, firmware checks `[sector+0x04]` equals the store's `this+0x59` byte granularity `g`, including `16` on BEE-encrypted NOR partitions).
  - `+0x06..+0x07` u16 reserved/metadata (plus zero/chunk padding up to `align_up(g, 8)` bytes).
- **Chunk 1 (`+align(8) .. +2*align(8)-1`, `+0x10..+0x1f` when `g = 16`):**
  - `+align(8)` u64 `sequence` (LE): the sector generation counter. `Mount` reads `Chunk 1` separately (`0x600cb830..0x600cb92c`): if `Chunk 1` is completely erased (`0xFF`), firmware assigns `sequence = 0xFFFFFFFFFFFFFFFF` (active unsealed sector accepting appends, or freshly formatted standby sector).
- **Records start at `sector + 2 * align_up(g, 8)`** (`+0x10` when `g <= 8`, `+0x20` when `g = 16`). Sector size is **not** needed by the plaintext parser: sectors are located by scanning `0x1000`-aligned offsets for `0xABCD` headers and delimited by the next accepted header or region end.

### Record (FACT unless noted)
Header 8 B (padded to `align_up(g, 8)` bytes; `16 B` when `g = 16`):
- `+0x00` u16 magic `0x55AA`
- `+0x02` u16 CRC (see §2)
- `+0x04` u16 flags; **bit 0 = record NOT live** (tombstone / pending-delete
  in the two-phase commit). Bits 1..15 undetermined, reported raw.
- `+0x06` u16 `(value_len << 4) | key_len`; key_len ∈ 1..15 enforced by the
  firmware (`strnlen(key, 16)`, GetValue rejects lengths outside 1..15).

Body: key (ASCII name) at `record + align(8)`; value at
`record + align(8) + align(key_len)`; total size
`align(8) + align(key_len) + align(value_len)` — align helper `FUN_602E2D6C`
(`0x60100b24` in `bruce`), size helper `FUN_602E2DB2` (`0x60100b6a` in `bruce`,
verified 3-chunk layout for all `g` including `g = 16`), read path `FUN_60203EA0`
(`GetValue`). **Alignment granularity `g`** is queried from the underlying
partition driver (`vtable+0x10` at `0x600cb72e`) and stored at `this+0x59`:
plaintext NOR drivers use `g in {1, 2, 4, 8}`, while the BEE-encrypted
internal flash driver enforces `g = 16` (`0x6005f320..0x6005f326`) so every
chunk (`Chunk 0`, `Chunk 1`, record header, key, and value) occupies a multiple
of the 16-byte AES-128 block. The parser auto-detects `g` across
`{4, 1, 2, 8, 16}` scored by CRC hits and header granularity (`--align N`
overrides). On raw FlexSPI NOR dumps inside `0x006000..0x03ffff` (ciphertext),
`detect_bee_sectors()` classifies 4 KiB sector occupancy structurally by
16-byte blocks (`standby_formatted`, `active_no_seq`, `active_sequenced`).

### Winner resolution — FACT (mount FUN_6020415E + GetValue FUN_60203EA0)
Per key, the firmware's RAM index keeps the record with the highest
(sector sequence, then offset within the sector walk). The index stores the
winner's flags bit 0; GetValue treats a winner with bit 0 set as **not
found**. Therefore: *latest record wins; if the latest is a tombstone, the
key reads as ABSENT* (it does not fall back to an older live record). The
parser implements exactly this and says so when a verdict rests on a
tombstone. (This refines the shorthand "the live record with the highest
position wins".)

The mount indexes records **without** validating CRCs; the CRC is checked
lazily on full reads (GetValue returns 0xF on mismatch). A winning record
with a bad CRC is therefore suspect: check `crc_ok` on the winner in the
JSON before trusting a verdict cell (§4).

## 2. Record CRC — REVERSED (FACT)

**Variant: CRC-16/CCITT-FALSE** — poly `0x1021`, init `0xFFFF`,
refin/refout false, xorout `0x0000`, MSB-first table-driven update
`crc = table[((crc >> 8) ^ byte)] ^ (crc << 8)`.

**Coverage**: the key bytes (key_len of them), then the value bytes
(value_len), chained through one state. No header bytes, no lengths.

Code evidence (gotham):
- `FUN_602E2E5C` (CRC wrapper, 52 B): builds the state struct, stores
  `movw r3, #0xFFFF` as the initial state, calls the update twice —
  (key, key_len) then (value, value_len).
- `FUN_60204DAC` (update): `table[((crc>>8) ^ b)] ^ (crc<<8)`, table pointer
  loaded from literal `DAT_60204DDC` = **0x60328C34**.
- Call sites: GetValue `FUN_60203EA0` (computes over the query key + the
  value just read; log "KVS CRC does not match for key=%s") and the record
  validator `FUN_60203FA2`.

Validation (run 2026-10-21, recorded here):
- The 512-byte table generated from poly 0x1021 matches the in-image table
  at 0x60328C34 **byte for byte**.
- `crc16("123456789") == 0x29B1`, the published CRC-16/CCITT-FALSE check
  value. (CRC-16/GENIBUS differs only by xorout 0xFFFF; the wrapper returns
  the raw state with no final complement, which is what fixes xorout = 0.)
- Bruce: wrapper `FUN_60100C14` is **instruction-identical** (same listing,
  init 0xFFFF, callee `FUN_600CC29C`) and
  the identical 512-byte table is present in the bruce image at VA
  `0x6011ACB6` (byte-for-byte match, verified this session). The bruce
  update callee was not separately dumped; variant identity for bruce rests
  on the identical wrapper + identical table + the triage's line-equivalence
  of GetValue/mount.

Parser behavior: CRC mismatch is a **warning** on raw records (`crc=BAD`),
never an abort, while `verdicts()` flags any bad-CRC winner as
`state="CRC_BAD"` (`crc_ok=false`, mirroring firmware `GetValue` rejecting
with `0xF`) instead of trusting it as `"LIVE"`.

**Hardware session verification (2026-11-15):** live hardware inspection of a
PVT `bruce 337784` unit revealed why raw FlexSPI NOR dumps of
`0x006000..0x03ffff` show no plaintext `0xABCD`/`0x55AA` markers: that entire
`0x3a000`-byte writable range is hardware-encrypted on flash via **i.MX RT106x
BEE Region 1 (`AES-128-ECB`)**, with `g = 16` (`0x10`) granularity (§3.1). On
live app mode (`18d1:9400`), reading `transfer_bug_report` (Bulk `op=9`)
already yields decrypted `BootloaderKvsMetadata` strings written through the
CPU/AHB BEE bus window (`AppAMeta`/`AppBMeta` Verified, `BookkeepMeta:
active=1, backup=2`), whose active/standby sector layout matches the
16-byte ciphertext blocks observed on raw NOR to the byte. Plaintext CRC-16
parsing remains ready whenever decrypted KVS slices (or unencrypted dev
regions) are supplied.

## 3. Partition discovery & parser usage (hardware session)

### 3.1 Resolved 13-partition table in NOR Flash — FACT (`bruce 337784` & `gotham 316382`)

Static disassembly of the board partition-table constructor in **`bruce` (`337784`)**
(`0x600740e2..0x60074580` on board singleton `0x200064c0`, registering `0x0d = 13`
descriptors in `board + 0x4378` via `0x600717a0`, constructing KVS instances via
`0x600d9c0a`) and the identical table in **`gotham` (`316382`)** (file offset
`0x6f764..0x6fade`, XIP `0x608af764..0x608afade`) resolves the physical NOR
offsets of all 13 firmware partitions plus Sector 0 (`FCB`), spanning all
4,096 × 4 KiB sectors (`16 MiB`) with zero unmapped gaps:

| 4 KiB sectors | Physical NOR | XIP address | Size | ID (`+0x08`) | KVS flags (`+0x09/+0x0a`) | Verified role |
|---|---|---|---:|---|---|---|
| `0x000..0x000` | `0x000000–0x000fff` | `0x60000000–0x60000fff` | 4 KiB | *(FCB)* | — | FlexSPI Configuration Block (`"FCFB"`) |
| `0x001..0x001` | `0x001000–0x001fff` | `0x60001000–0x60001fff` | 4 KiB | `0x12` (`18`) | `0, 0` | Boot IVT + `boot_data` read by Mask ROM (`board+0x4384`) |
| `0x002..0x003` | `0x002000–0x003fff` | `0x60002000–0x60003fff` | 8 KiB | `0x07` (`7`) | `0, 0` | Secondary crash / bug report store (`board+0x6740`, below write window) |
| `0x004..0x005` | `0x004000–0x005fff` | `0x60004000–0x60005fff` | 8 KiB | `0x0a` (`10`) | `0, 0` | Protected low partition (`board+0x4460`, below write window) |
| `0x006..0x027` | `0x006000–0x027fff` | `0x60006000–0x60027fff` | 136 KiB | `0x08` (`8`) | `0, 0` | Primary bug report / crash tombstone store (`bug_report.cc`) |
| `0x028..0x02f` | `0x028000–0x02ffff` | `0x60028000–0x6002ffff` | 32 KiB | `0x09` (`9`) | `1, 0` | **User / Runtime KVS (`id=9`)** (`board+0x4510`, erased on `FactoryReset` `0x600749ea`) |
| `0x030..0x033` | `0x030000–0x033fff` | `0x60030000–0x60033fff` | 16 KiB | `0x0b` (`11`) | `0, 0` | **Bluetooth bond NVRAM (`id=11`)** (`0x60065454`, erased on `FactoryReset` `0x60074a66`) |
| `0x034..0x037` | `0x034000–0x037fff` | `0x60034000–0x60037fff` | 16 KiB | `0x11` (`17`) | `0, 0` | Auxiliary data partition (`id=17`, `board+0x6700`) |
| `0x038..0x03b` | `0x038000–0x03bfff` | `0x60038000–0x6003bfff` | 16 KiB | `0x05` (`5`) | `1, 1` | **Factory / Persistent KVS (`id=5`)** (`board+0x5060`, survives `FactoryReset`: serial, `BruceMfgDate`, `DeviceColor`, calibration, `IsDfDevice`, `SsdpUdn`) |
| `0x03c..0x03f` | `0x03c000–0x03ffff` | `0x6003c000–0x6003ffff` | 16 KiB | `0x04` (`4`) | `1, 1` | **Bootloader Metadata KVS (`id=4`)** (`board+0x5bb0`: `AppAMeta`, `AppBMeta`, `RecoveryMeta`, `BookkeepVer`, `BookkeepMeta`) |
| `0x040..0x7ff` | `0x040000–0x7fffff` | `0x60040000–0x607fffff` | 7.75 MiB | `0x01` (`1`) | `0, 0` | Application Slot A (`bruce` / `gotham`, `board+0x4408`) |
| `0x800..0x81f` | `0x800000–0x81ffff` | `0x60800000–0x6081ffff` | 128 KiB | `0x03` (`3`) | `0, 0` | Bootloader Slot A (`zatanna`, `board+0x43b0`) |
| `0x820..0x83f` | `0x820000–0x83ffff` | `0x60820000–0x6083ffff` | 128 KiB | `0x13` (`19`) | `0, 0` | Bootloader Slot B (`board+0x43dc`; `id=4` in `zatanna`) |
| `0x840..0xfff` | `0x840000–0xffffff` | `0x60840000–0x60ffffff` | 7.75 MiB | `0x02` (`2`) | `0, 0` | Application Slot B (`gotham`, `board+0x4434`) |

Cross-check: `flash_lut.cc` init at `0x60067e44` configures two hardware layers
over the exact writable window `0x60006000` + length `0x3a000`
(`0x006000–0x03ffff`, sectors `0x006..0x03f`), leaving sectors `0x000..0x005`
(`FCB`, `Boot IVT`, `id=7`, `id=10`) outside normal application writes:

1. **i.MX RT106x BEE Region 1 bus encryption (`0x403EC000` BEE + `0x402FC000` DCP):**
   `0x600717d4` → `0x60067e44` → `0x6005f07c` enables **BEE Region 1 (`AES-128-ECB`)**
   across `[0x60006000, 0x60040000)` using key descriptor `0x601091f8`
   (hardware OTP key slot selected via `HW_OCOTP_CFG5` `BEE_KEY1_SEL` =
   `SW_GP2`/`OTPMK`). Because BEE decrypts AHB reads transparently in silicon
   while NOR flash writes use `0x6005f310` (DCP `AES-128-ECB` encryption prior
   to FlexSPI page programming), all writes inside `0x60006000–0x6003ffff`
   enforce **16-byte alignment (`g = 16`, `0x6005f320..0x6005f326`)**.
2. **Structural verification on captured `low_256k.bin` (PVT unit, 2026-11-15):**
   reading raw NOR pins via FlexSPI IPCMD (`0x402A8100`) yields raw ciphertext
   with clean `0xFF` tails strictly ending on 16-byte block boundaries (`% 16 == 15`),
   matching `g = 16` (`Mount` `0x600cb6fc` formats standby sectors by writing
   Chunk 0 `+0x00..+0x0f`, leaving `Chunk 1` `+0x10..+0x1f` erased until sealed,
   and appending records from `+0x20`):
   - `user_kvs` (`id=9`, `0x028000–0x02ffff`, 8 sectors): `sec[1]` active
     (`active_no_seq`, `23` record blocks = `368 B`, `erased_tail = 3696 B`) +
     `7` `standby_formatted` sectors (`1` header block each, `erased_tail = 4080 B`).
   - `factory_kvs` (`id=5`, `0x038000–0x03bfff`, 4 sectors): `sec[1]` (`active_no_seq`,
     `159` record blocks, `erased_tail = 1520 B`), `sec[2]` (`active_no_seq`, `107`
     record blocks, `erased_tail = 2352 B`), plus `sec[0]` & `sec[3]` `standby_formatted`.
   - `bootloader_kvs` (`id=4`, `0x03c000–0x03ffff`, 4 sectors): `sec[1]`
     `active_sequenced` (`Chunk 0` + `Chunk 1` sequence + `252` record blocks,
     `erased_tail = 32 B`), `sec[2]` `active_no_seq` (`136` record blocks,
     `erased_tail = 1888 B`), plus `sec[0]` & `sec[3]` `standby_formatted` —
     matching the live `BookkeepMeta: active=1, backup=2` state reported by the
     controller over USB Bulk `transfer_bug_report` (`op=9`).
   - `bug_reports` (`id=8`: `32` × 16 B blocks), `bt_nvram` (`id=11`: `128` ×
     16 B blocks), and `aux_data_17` (`id=17`: `210` × 16 B blocks) also hold
     high-entropy 16-byte ciphertext blocks ending cleanly on 16-byte boundaries.

### 3.2 Parser CLI invocation

For a surgical low-256 KiB capture (`low_256k.bin` starting at `0x60000000`),
inspect and carve all partitions offline (with automatic redaction of sensitive
serials/UDNs by default) using `tools/nor_slice_inspect.py`:

```bash
python3 tools/nor_slice_inspect.py low_256k.bin --base-offset 0x60000000 \
  --extract-dir ./carved_local --json low_256k_report.json
```

Or invoke `tools/kvs_parse.py` directly against the exact carved KVS regions
(or the whole `low_256k.bin@0x60000000` / `full.bin@0x60000000`):

```bash
python3 tools/kvs_parse.py \
  --region ./carved_local/user_kvs.bin@0x60028000 \
  --region ./carved_local/factory_kvs.bin@0x60038000 \
  --region ./carved_local/bootloader_kvs.bin@0x6003c000 \
  --json kvs_result.json
```

CLI defaults to `--sector-align 0x1000` (4 KB NOR erase sectors) so embedded `0xABCD` bytes inside record payloads cannot trigger false sector splits; pass `--sector-align 0` only for synthetic/unaligned sub-slices. For BEE-encrypted raw dumps in `0x60006000..0x6003ffff`, `kvs_parse.py` reports `bee_encrypted: true` (`align: 16`) and lists per-sector `bee_sectors` state (`standby_formatted`, `active_no_seq`, `active_sequenced`) and 16-byte block counts. For plaintext KVS regions, output includes the full record listing (offset, sector sequence, key, flags, LIVE/DEAD, CRC status, value as hex + u32 + ASCII), sector table (with TORN-TAIL flags), the verdict block (§4, emitting `CRC_BAD` if the winner failed CRC), and any equal-sequence cross-sector `ambiguities`.

Self-test (no hardware): `python3 tools/kvs_parse.py --selftest` builds synthetic sectors (including `g=4` and `g=16`/`version=4` headers with `records_offset=0x20`, erased `Chunk 1` sequence handling, an aborted dead write superseded by live records, an empty-value `SsdpUdn`, a tombstone-only key, a torn sector tail, a bad-CRC winning record, an embedded `0xABCD` guard, sequence-collision ambiguity surfacing, and BEE AES-128-ECB sector classification) and asserts all verdicts. `python3 tools/nor_slice_inspect.py --self-test` tests partitioning across all 10 regions in the low 256 KiB slice (`FCB` + 9 partitions), BEE-encrypted KVS reporting, partial Slot B header decoding, and redaction. Negative control: run `kvs_parse.py` against a plaintext firmware app image, the parser finds 0 sectors and reports all keys ABSENT.

## 4. Decision table

Background (FACT, triage Part 1; leg A clarified 2026-11-15 via issue #3):
the vendor echo condition in gotham/bruce is `A OR B`, where **A** = on-chip
OCOTP silicon fuse field `0x26` bit 8 (in bruce: `FUN_600d9934` →
`FUN_60071348(0x26)` → ITCM `FUN_00001084(0x401F4000, 0x26, &out, 4)` reading
the i.MX RT1060 OCOTP controller at `0x401F4000`, rather than a companion-chip
button-combo register as earlier notes assumed), and **B** = the dynamic
`IsDfDevice` value (config ID `0x16` passed to `FUN_600d72ec(0x16, …)` — the
compile-time enum index in `keys.cc` that resolves to the ASCII flash key
`"IsDfDevice"`, falling back to the compiled default FALSE when no live record
exists; enumerating all `FUN_60101198` / `0x600d7140..0x600d7250` writers in
bruce shows no firmware path writes key `0x16`). `key_index = 3` in a challenge
response ⟺ the condition was true at that moment. A KVS dump can only ever
show B directly; A is decided by elimination. The echo token is compared
against the unit's challenge string (`SsdpUdn` / OCRAM `0x2000d1d5`): in
`bruce`, Route A (`0x60077d98..0x60077dae`) compares the token directly against
the static `0x2000d1d5` string (`strlen` + `memcmp`), whereas the runtime
counter appended at `ctx+0x1380` is consumed by the Route B ECDSA SHA-256
digest (FACT for gotham: `device_info`'s `SsdpUdn` is initialized from KVS
key 4; a stored empty value suppresses regeneration — the generator
`FUN_600836B0` fires only when the key is *not found*, initializer
`FUN_60083968`).

`IsDfDevice` columns: **live=1** / **live=0** / **absent** (no live record,
including tombstone-latest; compiled default FALSE applies).
`SsdpUdn` rows: **nonempty** / **empty** / **absent**.

| IsDfDevice ↓ / SsdpUdn → | nonempty | empty | absent |
|---|---|---|---|
| **live = 1** | (i) **B proven ON** (factory provisioning stored in KVS). A unknown, irrelevant. (ii) Token = the stored SsdpUdn bytes exactly. | (i) **B proven ON**. (ii) Token = **empty** (length 0). | (i) **B proven ON**. (ii) SsdpUdn absent ⇒ firmware generates a UDN at first init and stores it; token = that generated string as emitted in the challenge response (nonempty). "Absent" in a dump from a booted unit is anomalous (wrong partition or pre-init dump). |
| **live = 0** | (i) B explicitly OFF (stored 0 overrides default). With key_index=3 observed, **A is the active leg** (elimination). (ii) Token = the stored SsdpUdn bytes exactly. | (i) B OFF ⇒ **A active** (elimination, given key_index=3). (ii) Token = **empty**. ★ | (i) B OFF ⇒ **A active**. (ii) Token = the generated UDN from the challenge response (nonempty). ⚠ inconsistent with this unit's observed empty challenge response; if a dump lands here, re-examine which partition was dumped. |
| **absent** (default FALSE) | (i) B OFF (default) ⇒ **A active** (elimination). (ii) Token = the stored SsdpUdn bytes exactly. | (i) B OFF (default) ⇒ **A active** (elimination). (ii) Token = **empty**. ★ | (i) B OFF (default) ⇒ **A active**. (ii) Token = generated UDN (nonempty). ⚠ same inconsistency as live=0/absent; treat as anomaly. |

★ = the two cells consistent with everything observed on this unit so far
(key_index=3 across boots, challenge response carrying no string, and the
successful empty-token unlock): **SsdpUdn stored EMPTY, the echo condition
carried by leg A (OCOTP fuse `0x26` bit 8), IsDfDevice either explicitly 0 or
absent.** A dump landing in a ★ cell closes the property question by the
physical route; the IsDfDevice column then only decides whether the unit
was *also* factory-provisioned.

**Bruce transfer & resolved dual-path reconciliation (2026-11-13; fuse backing & live verification updated 2026-11-15):** format, CRC, and winner semantics are verified identical in bruce (§1, §2 — FACT). The earlier echo-token observation (`triage Part 1`: `key_index = 3`, `A OR B` gate, echo memcmp against `SsdpUdn`, "successful empty-token unlock") and the later ECDSA trace in `README.md` §7.1.1 are **both real — they are the two branches of the same unlock handler** (disasm `0x60077d92`): the `(OCOTP fuse 0x26 bit 8 OR IsDfDevice)` gate selects an echo-memcmp path (challenge `strlen`+`memcmp`; a SsdpUdn-less unit yields an empty challenge, hence the empty-token success), and only when that gate fails does kind 2 fall through to ECDSA P-256 verification against Google's embedded PEM keys. Full path detail in `README.md` §7.1.1; §9 item 6 closed. Live hardware probing on a `ReadyForEndUserUse` `bruce 337784` unit (`18d1:9400`) confirmed that `0x2000d1d5` holds the 36-char `SsdpUdn` UUID (returned by both `EP0 IN 0x87` and `UnlockChallengeResponse.field_1`) and `0x2000d168` holds the 14-char `DevSerial` (`UnlockChallengeResponse.field_2`), with `UnlockChallenge` (`08 01 18 01`) succeeding pre-unlock (`required_mask = 0`) and returning `key_index = 2`; raw FlexSPI NOR dumps confirmed that `id=9` and `id=5` sit inside the hardware-encrypted BEE Region 1 window (§3.1, `AES-128-ECB`, `g = 16`).

## 5. What remains open

- ~~Reconcile `key_index = 3` / `A OR B` echo-unlock notes (§4) with the `ECDSA P-256` gate documented in `README.md` §7.1.1.~~ **Resolved 2026-11-13; fuse backing closed 2026-11-15 (issue #3):** dual-path unlock confirmed in disassembly — echo-memcmp behind the `(OCOTP fuse 0x26 bit 8 via FUN_00001084 @ 0x401F4000 OR IsDfDevice)` gate (with no `bruce` writer for KVS key `0x16`), and ECDSA P-256 as the fallback for end-user units.
- **Plaintext on-flash record CRC verification vs BEE ciphertext (§1–§3.1):**
  the CRC-16/CCITT-FALSE algorithm is proven against both firmware tables
  and test vectors (§2), and the hardware dump of `0x006000..0x03ffff`
  proved why FlexSPI IPCMD captures of `id=9`, `id=5`, and `id=4` yield
  16-byte-aligned `AES-128-ECB` ciphertext (`g = 16` under BEE Region 1)
  rather than plaintext `0xABCD`/`0x55AA` headers. End-to-end offline CRC-16
  parsing of genuine KVS records therefore requires a CPU-bus (AHB-decrypted)
  dump or an unencrypted development unit.
- ~~Alignment granularity (`this+0x59`) and sector header bytes `+0x04..+0x07`~~
  **Resolved (2026-11-15):** disassembly of `Mount` (`0x600cb89c` in `bruce`)
  and `flash_lut.cc` (`0x6005f320`) confirms `sector+0x04` (`u16`) stores the
  granularity `g` for `version in (3, 4)` (`version == 2` forces `g = 1`),
  `sequence` (`Chunk 1`) sits at `+align_up(g, 8)` (`0xFF` = unsealed
  `0xFFFFFFFFFFFFFFFF`), and records start at `+2 * align_up(g, 8)` (`+0x20`
  when `g = 16` under BEE). Header `+0x06..+0x07` and record `flags` bits
  1..15 remain reserved/reported raw.
- ~~The concrete NOR offsets of the KVS partitions (gotham ids 9 and 5)
  remain statically undetermined (triage open item 1)~~ **Resolved (2026-11-15):**
  disassembly of `board+0x4378` (`bruce 337784` `0x600740e2..0x60074580`,
  `gotham 316382` `0x608af764..0x608afade`) places all three KVS instances inside
  the first 256 KiB of NOR (§3.1): `id=9` User KVS at `0x028000–0x02ffff`
  (`0x60028000`, 32 KiB), `id=5` Factory/Persistent KVS at `0x038000–0x03bfff`
  (`0x60038000`, 16 KiB), and `id=4` Bootloader Metadata KVS at `0x03c000–0x03ffff`
  (`0x6003c000`, 16 KiB).
