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

### Sector header (16 B) — FACT (triage Part 2; mount FUN_6020415E)
- `+0x00` u16 magic `0xABCD`; `+0x02` u16 version, accepted 2..4.
- `+0x04..+0x07` metadata bytes, semantics undetermined; the parser reports
  them raw in the JSON (`meta_4_7`) and does not interpret them.
- `+0x08` u64 sequence (LE): the sector generation counter. The mount keeps,
  per key, the record from the sector with the highest sequence.
- Records start at sector + 16. Sector size is **not** needed by the parser:
  sectors are located by scanning for headers and delimited by the next
  accepted header or the end of the region. An erased sector is all-`0xFF`
  and has no valid header, so it never appears as a sector.

### Record (FACT unless noted)
Header 8 B:
- `+0x00` u16 magic `0x55AA`
- `+0x02` u16 CRC (see §2)
- `+0x04` u16 flags; **bit 0 = record NOT live** (tombstone / pending-delete
  in the two-phase commit). Bits 1..15 undetermined, reported raw.
- `+0x06` u16 `(value_len << 4) | key_len`; key_len ∈ 1..15 enforced by the
  firmware (`strnlen(key, 16)`, GetValue rejects lengths outside 1..15).

Body: key (ASCII name) at `record + align(8)`; value at
`record + align(8) + align(key_len)`; total size
`align(8) + align(key_len) + align(value_len)` — align helper `FUN_602E2D6C`
(round up to a multiple), size helper `FUN_602E2DB2`, read path `FUN_60203EA0`
(GetValue). **Alignment granularity** is a runtime byte of the store object
(+0x59) whose concrete value is not statically fixed (triage open item;
probably 4 — INFERENCE). The parser auto-detects it: it walks the dump with
each candidate in {4, 1, 2, 8} and keeps the walk scoring highest on
(CRC-valid records, clean sectors, record count). `--align N` overrides.

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

**Still untested**: no genuine on-flash KVS record has ever been parsed (no
NOR dump of the KVS region exists yet). The CRC is proven against the
firmware's own tables and the catalogue check value, and the parser
end-to-end against synthetic data (§3), but the first real dump is the
first end-to-end test against a real record. If that dump yields zero
CRC-valid records under every alignment, stop and revisit §1/§2 before
drawing verdicts.

## 3. Parser usage (hardware session)

Feed it every region file with the NOR address of its first byte:

```bash
python3 tools/kvs_parse.py \
  --region kvs.bin@0x60940000 \
  --json kvs_result.json
```

(Earlier triage drafts used `--region gap1.bin@0x60002000 --region gap2.bin@0x60424000 --region tail.bin@0x60C24000`, which reflected pre-`README.md` §1 slice names; a single full-NOR dump is `--region full.bin@0x60000000`.) CLI defaults to `--sector-align 0x1000` (4 KB NOR erase sectors) so embedded `0xABCD` bytes inside record payloads cannot trigger false sector splits; pass `--sector-align 0` only for synthetic/unaligned sub-slices. Output: full record listing (offset, sector sequence, key, flags, LIVE/DEAD, CRC status, value as hex + u32 + ASCII), sector table (with TORN-TAIL flags), the verdict block (§4, emitting `CRC_BAD` if the winner failed CRC), any equal-sequence cross-sector `ambiguities`, and the JSON file with the same fields.

Self-test (no hardware): `python3 tools/kvs_parse.py --selftest` builds synthetic sectors (an aborted dead write superseded by live records, a newer sector winning over an older one, an empty-value `SsdpUdn`, a tombstone-only key, a torn sector tail, an erased sector, a bad-CRC winning record, an embedded `0xABCD` false-positive test over the CLI `main()` path, and sequence-collision ambiguity surfacing) and asserts the verdicts. Negative control: run against the gotham app image itself, the parser finds 0 sectors and reports all keys ABSENT.

## 4. Decision table

Background (FACT, triage Part 1): the vendor echo condition in gotham is
`A OR B`, where **A** = companion-chip mailbox register 0x26, inverted bit 8,
and **B** = the dynamic `IsDfDevice` value (falling back to the compiled
default FALSE when no live record exists). `key_index = 3` in a challenge
response ⟺ the condition was true at that moment. A KVS dump can only ever
show B directly; A is decided by elimination. The echo token is compared
against the unit's challenge string, which is its `SsdpUdn` value (FACT for
gotham: the challenge field is device_info's `SsdpUdn`, initialized from KVS
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
carried by leg A (companion register), IsDfDevice either explicitly 0 or
absent.** A dump landing in a ★ cell closes the property question by the
physical route; the IsDfDevice column then only decides whether the unit
was *also* factory-provisioned.

**Bruce transfer & unresolved ECDSA discrepancy:** format, CRC, and winner semantics are verified identical in bruce (§1, §2 — FACT). The echo-token claim (`triage Part 1` / prior `bruce` USB notes: `key_index = 3`, `A OR B`, `echo memcmp` against `SsdpUdn`, `"successful empty-token unlock"`) conflicts with the later `2026-11-13` bulk-channel trace in `README.md` §7.1.1 (which observed `kind 2` requiring an ECDSA P-256 signature over the challenge hash against embedded Google PEM keys). Reconciling whether `key_index == 3` / `A OR B` is a separate factory branch or an obsolete note remains open (see §5 and `README.md` §9 item 6). Additionally, whether bruce's challenge string is seeded from its KVS `SsdpUdn` record was not traced and remains open.

## 5. What remains open

- Reconcile `key_index = 3` / `A OR B` echo-unlock notes (§4) with the `ECDSA P-256` gate documented in `README.md` §7.1.1.
- The CRC is fully reversed and validated against the firmware's own tables
  (§2); it is **not** yet validated against a genuine on-flash record,
  because no KVS dump exists yet. First real dump = first end-to-end test.
- Alignment granularity: auto-detected by the parser (CRC-scored), not
  statically fixed. If a real dump produces no CRC-valid records under any
  candidate alignment, the format assumptions in §1 must be revisited
  before any verdict is drawn.
- Sector header bytes +4..+7 and record flags bits 1..15: uninterpreted
  (reported raw). Neither affects the verdict keys (IsDfDevice, SsdpUdn,
  UpdateGauge).
- The concrete NOR offsets of the KVS partitions (gotham ids 9 and 5)
  remain statically undetermined (triage open item 1); the parser does not
  need them - it finds sectors by header scan anywhere in the dumped
  regions.
