## Current live revision — packaging (2026-11-09)

Packaging only: the 16-round function, S-boxes, schedule, mixes, bow, rehair and
cross-staff layers are unchanged from the beat-0 pressure-rotation revision below.
Still homemade. **Not for real secrets.** Use AES-GCM-SIV, age or libsodium.

Triggered by the independent review in [issue #1](https://github.com/Kromatikus/octavo/issues/1)
(@liqdmetal): no cipher break reported, but a fresh clone could not run the suite
or the advertised quick start.

### Seed path

`SEED_PATH` is `sneak1024-seed.txt` next to this module (`os.path.dirname(abspath(__file__))`).
`load_seed()` with no argument reads only that file; there is no other fallback path.
The runtime absolute value of `SEED_PATH` is listed in `_ATTEST_SKIP` and is
**not** hashed into `mix_description`, so two installs of the same source produce
the same `key_signature`.

### Key signature (cached, embedded)

`mix_description()` is still the canonical JSON of parameters plus length-framed
function sources and reachable module data. It is computed from source when
`inspect.getsource` works.

`EXPECTED_MIX_SHA256` is `sha256(mix_description())` stored in the module. It is
also in `_ATTEST_SKIP`, so the constant is not part of what it names
(chicken-and-egg). At import:

1. If source is readable, compute the digest and compare it to `EXPECTED_MIX_SHA256`.
   A mismatch raises `RuntimeError`.
2. If source is not readable (a `.pyc`-only install), use the embedded digest.

`key_signature(seed)` is `StaffSponge(b"G", seed, bytes.fromhex(digest)).take(16)`.
The sponge nonce is the 32-byte digest, not the full JSON. That is a packaging
change to the commitment encoding; the round function is untouched. Encrypt and
decrypt therefore no longer re-parse source on every call.

`MIX_CODE_ROOTS` includes `mix_description` so the description helpers and the
data they name stay in the closure. In-process monkeypatches after import still
change a fresh `mix_description()`, but they do **not** move the cached
`key_signature`. A changed *file* (with `EXPECTED_MIX_SHA256` left as
`TO_BE_FILLED` or updated) computes a new digest at import and so a new
`key_signature`.

### Blob format version

Blobs are 196 bytes:

```
version (1 byte, FMT_VERSION = 1) || SN2 || pickup (16) || nonce (16) || ct (128) || tag (32)
```

Offsets: version `[0:4]` (the version byte plus `SN2`), pickup `[4:20]`, nonce
`[20:36]`, ciphertext `[36:164]`, tag `[164:196]`.

`decrypt` checks the first byte before the length and before the tag. A blob
whose first byte is not `1` — including every older 195-byte `SN2...` blob —
raises `UnsupportedVersion("unsupported version")`. The HMAC authenticates
`clef || key_sig || version || SN2 || pickup || nonce || ct`. Sponge domain
strings remain `b"SN2/"`.

### Weak seeds

`_seed_bytes` rejects a 128-byte seed with fewer than 32 distinct nonzero bytes
(`ValueError: weak seed: need at least 32 distinct nonzero bytes`). Integer
`1` and the all-zero key are rejected. The published demo seed has 100 distinct
nonzero bytes and is accepted.

---

# Sneak staff-core N2: live specification

## Previous revision — beat-0 pressure rotation fix (2026-11-09)

This section supersedes everything below for the bow, including the beat-6 section that
follows. Still N2 / SN2 (project name: Octavo), still homemade, **not for real secrets** (use
AES-GCM-SIV, age or libsodium). `BOW_STROKES` unchanged; new `BOW_PRESSURE_ROT` and updated
`bow_pressure` / `unbow_pressure`. No table name, sponge domain, blob format or API changed.
No PNG, renderer, seed, frozen snapshot, attack folder, baseline, GitHub clone or demo-nonce
was changed; the picture is stale (previous revision's hello-world cells).

**Motivation** (`attacks_octavo_beat6/REPORT.md` §6). Three strokes share beat 0's rotations.
Proposed and lab-screened fix: distinct views of beat 0 before r1/r2.

**Live bow.**

```
BOW_STROKES      = (0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)   # (i, j, pressure)
BOW_PRESSURE_ROT = (0,    0,    0,     3,     0,     0,     5    )           # per-stroke rotl of p
view = rotl8(pressure_byte, BOW_PRESSURE_ROT[stroke_index])
r1 = 1 + view%7 ; r2 = 1 + (view>>3)%7
u = (u + rotl8(v,r1)) & 255 ; v ^= rotl8(u,r2)
```

`(4,5,0)` uses `p`; `(6,7,0)` uses `rotl8(p,3)`; `(5,6,0)` uses `rotl8(p,5)`. Non-beat-0
readers use rot 0 (identity). `unbow_pressure` applies the same views in reverse stroke order.
Beat 0 is written only by stroke `(0,1,2)`, before every later reader, so the bow stays
invertible.

**No-singleton arguments** (any base, any delta, any tables). Each uses only "pressure byte
unchanged ⇒ rotations fixed" (still true under a fixed per-stroke function of p) and that
`x ↦ x+c`, `x ↦ x⊕c` are bijections:

* **Beat 0 (written).** Stroke `(0,1,2)` has fixed rotations (beat 2 unchanged), so
  `u = s0 + rotl(s1)` changes. Beat 0's final value is that `u`, and s1 changes. Stroke
  `(2,3,4)` is untouched, so `(1,2,3)` has fixed rotations: beat 1 changes, then beat 2
  changes. Neither is written again. Outputs 0, 1 and 2 change → two rehair pairs.
* **Beat 4 (written).** Stroke `(4,5,0)` reads beat 0, which beat 4 cannot reach before
  stroke 3, so its rotations are fixed. u3 changes and beat 5 changes. `(6,7,0)` is
  untouched. `(5,6,0)` has fixed rotations: beat 5 changes, then beat 6 changes. Outputs 5
  and 6 change → two pairs.
* **Beat 6 (written; unchanged by this fix).** Outputs 5 and 7 always change (pairs (4,5)
  and (6,7)). See the beat-6 section below.
* **Beat 7 / odd beats (written; unchanged).** See the beat-7 section below.
* **Beat 2 (measured only; partial proof).** If the bow's beat-0 output is unchanged
  (~15% of cases), strokes that read beat 0 are untouched and outputs 3 and 4 always change.
  Otherwise: measured ≥ 3 active pairs in all sampled cases; no complete written argument.

**Verified / identifiers.**
- Live `sneak_n2.py` SHA-256: `25cfe812ac6a5d5c22a26ba17440843f417dd44e060498850a78b68964612ff0`.
- key_sig: `1946c5ac57f19d045eeacd9e5ed823fb` (changes with `BOW_PRESSURE_ROT` and the bow
  sources; closure data names now 36, including `BOW_PRESSURE_ROT`).
- Previous sample pickup `d450337d…` → tag mismatch. Backup: `/tmp/sneak_n2_pre_beat0rot`.
- New hello-world pickup `7d4b4694011a7ab66e7f5f24c235c3f8`.
- Scan folder: `/workspace/sneak_n2/fix_beat0rot_verification/` — A: 0/534.8 M per even beat
  (2^21); B: 0 on all 8 beats (2^18); diffs beat 0/6/7 → 2^-10.19 / 2^-7.07 / 2^-7.33.
  Forced changes: beat 0→{0,1,2}, beat 4→{5,6}, beat 6→{5,7}. Does not modify any `attacks_*`.
- Tests: **237/237 passed**. Picture / `render_n2.py` untouched (stale).

**Honest limits.** Fixed-rotation ARX integrals/cubes when beat 0 is constant remain; this
fix only splits the shared `(r1,r2)`. Still homemade — use AES-GCM-SIV, age, or libsodium.

---


## Previous revision — beat-6 bow fix (2026-11-09)

This section supersedes everything below for the bow, including the beat-7 section that
follows. Still N2 / SN2 (project name: Octavo), still homemade, **not for real secrets** (use
AES-GCM-SIV, age or libsodium). One constant changed; no function, table name, sponge domain,
blob format or API changed. No PNG, renderer, seed, frozen snapshot, attack folder, baseline or
demo-nonce was changed; the picture is stale.

**What the attack found** (`attacks_octavo_beat7/REPORT.md`, issue 1). The beat-7 fix only
argued odd beats, and the strict test only scanned odd beats. A larger scan over all eight
beats found rare single-byte leaks from **beat 6**: about 1 in a million beat-6 changes
(19 in 16.7 M in the cleanest run; table-independent; 3 witnesses stayed single-byte under all
16 round tables). Mechanism, from witness `[90,8,17,194,106,100,92,5]`, beat 6 ^ 28: stroke
`(4,5,6)` read beat 6, so its r2 changed and beat 5 shifted; `(3,4,5)` happened to keep its
rotations; `(5,6,0)` then added the changed beat 6 into beat 5 and cancelled the shift. The
final bow delta `(…,0,36,18)` sat in rehair pair (6,7) with du = 2·dv, the Latin pair's
y-kernel, so exactly one byte changed. Same trap as the old beat-7 problem, one stroke earlier.

**The change.** Third bow stroke `(4,5,6)` -> `(4,5,0)` (pressure read from beat 0, which no
stroke writes after `(0,1,2)`). Live bow:

```
BOW_STROKES = (0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)   # (i, j, pressure)
r1 = 1 + p%7 ; r2 = 1 + (p>>3)%7 ; u = (u + rotl8(v,r1)) & 255 ; v ^= rotl8(u,r2)
```

Stroke formula, rotations, order, the no-(7,0)-pair rule and the odd rehair are unchanged.
`unbow_pressure` still undoes the strokes in reverse; the pressure cell is never written by its
own stroke (beat 0 is only written by stroke 1, before every stroke that reads it), so
inversion is exact (tested: 20,000 random + uniform staffs two-sided, full-cipher round trips).

**Beat 6, by argument (any base, any delta, any tables).** Beat 6 is now read as pressure by no
stroke. Strokes 1-3 don't touch it. `(6,7,0)` has fixed rotations (beat 0 unchanged), so
u = s6 + rotl(s7) changes and s7' = s7 ^ rotl(u, r2) changes; beat 7 is never written again.
`(1,2,3)` and `(3,4,5)` don't see beats 5-7 changed (beat 5 is still unchanged, so `(3,4,5)`
has fixed pressure and unchanged inputs). `(5,6,0)` has fixed rotations and adds the changed
beat 6 into an unchanged beat 5, so beat 5 changes. Beats 5 and 7 therefore both change, in
rehair pairs (4,5) and (6,7); a singleton needs the bow delta inside one pair, so the rehair
changes at least 2 bytes. The beat-7, beat-5, beat-3 and beat-1 arguments in the section below
still hold unchanged (for beat 5, `(4,5,0)` has fixed pressure, so it always changes beat 4).

**Even beats 0, 2, 4: measured only, not proved.** 0 singletons in every scan below, but there
is no written argument for them.

**Correction to the beat-7 section below.** It said "a random 400,000-case scan over all 8
beats: 0 bow+rehair singletons on every beat". That scan (about 50,000 cases per beat) was far
too small to see a ~1e-6 per-case rate, so it said nothing about beat 6. It was not evidence
that even beats were clean.

**Verified.**
- Strict test, now **all 8 beats** (512 bases x 8 beats x 255 deltas = **1,044,480** cases,
  same protocol; odd subset = the old 522,240): bow+rehair singletons per beat
  **[0,0,0,0,0,0,0,0]**, min 2 changed bytes; 0x80 deltas 0/4,096. Bow alone (before rehair):
  [0,93,0,120,0,127,0,808] = 1,148 (was 1,083 on odd beats), all absorbed by the rehair.
- Beat-6 scan (NumPy model of bow + live round-0 rehair, checked against the live
  `bow_pressure`/`odd_restack` on 5,000 staffs): **0 / 16,711,680** beat-6 cases (65,536
  random bases x 255 deltas) and 0 / 4,177,920 on each other beat. The same scan with the old
  `(4,5,6)` layout patched in finds 17 beat-6 singletons (negative control, not in the suite).
- The 4 pre-fix beat-6 witnesses (the 3 all-table ones plus the mechanism example) now change
  4 bytes under all 16 rounds' tables; with `(4,5,6)` patched back in they are single-byte
  again (negative-control test).
- Lemma test: 200,000 random beat-6 changes never touch beats 0-4 and always change beats 5
  and 7. The beat-7 lemma (200,000) still passes.
- Key signature: no new functions or tables. `BOW_STROKES` is in the `mix_data` digest, so
  key_sig and every tag changed. Closure still 57 code names (all in the 62-name
  `MIX_CODE_FUNCS`) and 35 data names.
- Previous hello-world sample (pickup `ee95ddb278a849bae4a34fe594ee87e5`) fails with tag
  mismatch. Pre-change copy: `/tmp/sneak_n2_pre_beat6`.
- Speed unchanged (encrypt+decrypt about 79-80 ms both before and after on the box).
- Tests: **229/229 passed** (222 before, plus 7 new checks: beat-6 lemma, no stroke reads beat 6,
  the 4 witnesses, a `(4,5,6)` negative control, NumPy-model equality, the 16.7 M beat-6 scan, and
  the previous sample failing on tag; the strict singleton test was widened from odd beats to all
  8 beats, and the bow-stroke literal check now pins `(4,5,0)`). Full suite about 7-14 min.

**Honest costs.**
- Beat 0 now feeds the rotations of **three** strokes (`(4,5,0)`, `(6,7,0)`, `(5,6,0)`), so
  with beat 0 fixed those three are fixed-rotation ARX. That deepens the shared-rotation
  structure from the attack report (issue 2).
- Bow-alone best beat-6 differential gets worse, about 2^-7.75 -> about 2^-5.68 (lab figure
  from `attacks_octavo_beat7/attack_fix_sidefx_results.json`); beat 7 stays about 2^-4.8. The
  rehair S-boxes absorb this: bow+rehair best differential was ≤ 2^-13 on every beat in the lab.
- Bow-alone single-byte changes rise (lab: 6,721 -> 7,835 per 8.36 M all-beat cases; strict
  test 1,083 -> 1,148). None survive the rehair.
- Not fixed and not touched: the bow 2-bit linear relation (−0.145, capped at 0.0037 by the
  rehair), the bow single-bit 0.039 relation, and the three in-process key-signature blind
  spots from the report.
This is a fix to one local property; it is not evidence the cipher is secure.

## History — beat-7 bow fix (2026-11-09, superseded above for the bow)

This section superseded everything below for the bow (now itself superseded by the beat-6 section above). Still N2 / SN2, still homemade,
**not for real secrets** (use AES-GCM-SIV, age or libsodium). One constant changed; no
function, table name, sponge domain, blob format or API changed. No PNG, renderer, seed,
frozen snapshot, attack folder, baseline or demo-nonce was changed; the picture is stale.

**Root cause of the 5 singletons.** A rehair (odd-restack) pair can only leave a single
changed byte if the bow's output change sits entirely inside that one pair, in both cells,
with du = dv or du = 2dv (the field step's kernel; true of any 2-cell Latin pair, so no other
matrix can remove it). For a beat-7-only change, the old last bow stroke `(5,6,7)` read its
pressure from beat 7. Beat 7 had changed, so that stroke's rotations changed too, and the change
to beat 6 could be rotated into exactly the same addend for beat 5. Beat 5 then came out
unchanged, the whole bow delta stayed in pair (6,7), and 5 of 522,240 scanned cases hit the
kernel. All 5 were beat 7 and table-independent.

**The change.** Last bow stroke `(5,6,7)` -> `(5,6,0)` (pressure read from beat 0, which no
stroke writes after `(0,1,2)`). Live bow:

```
BOW_STROKES = (0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,0)   # (i, j, pressure)
r1 = 1 + p%7 ; r2 = 1 + (p>>3)%7 ; u = (u + rotl8(v,r1)) & 255 ; v ^= rotl8(u,r2)
```

Stroke formula, rotations, order, the no-(7,0)-pair rule (only pressure reads may wrap) and
the odd rehair (keyed Latin pairs (0,1),(2,3),(4,5),(6,7): x=u^v, y=u^gf_mul(2,v), u'=S[x],
v'=S2[y]) are unchanged. `unbow_pressure` still undoes the strokes in reverse; the pressure
cell is never written by its own stroke, so inversion is exact.

**Why there are now 0 odd-input singletons (argument, any base, any delta, any tables).**
A pair whose input changes in one cell only changes both outputs (Latin property), and a
change spread over two pairs changes at least one output in each, so a singleton needs a bow
delta inside one pair, in both cells.
- Beat 7: strokes 1-3 and 5-6 don't touch it. `(6,7,0)` (pressure beat 0, unchanged) always
  changes beat 6. `(5,6,0)` has fixed rotations and fixed beat 5 input, so beat 5 always
  changes; beat 4 never does. Pair (4,5) gets a one-cell change, so >=2 output bytes change.
- Beat 5: `(4,5,6)` always changes beat 4. If beat 5 ends changed, `(5,6,0)` (fixed pressure,
  fixed beat 6) also changes beat 6, a second pair. Otherwise no pair holds a two-cell delta.
- Beat 3: `(2,3,4)` always changes beat 2. If beat 3 ends changed, `(3,4,5)` (fixed pressure,
  fixed beat 4) also changes beat 4, a second pair. Beat 0 never changes.
- Beat 1: `(0,1,2)` always changes beat 0, which nothing writes later. If beat 1 ends
  changed, `(1,2,3)` (fixed pressure, fixed beat 2) also changes beat 2.
With the old `(5,6,7)`, beats 1, 3 and 5 had the same argument; only beat 7 broke.

**Verified.**
- Strict test (522,240 odd-input cases, all 255 deltas, test protocol): bow+rehair singletons
  **0** (was 5), min 2 changed bytes; 0x80 0/2,048. A random 400,000-case scan over all 8 beats:
  0 bow+rehair singletons on every beat (old code: 1 on beat 7). [Correction: too small to see a
  ~1e-6 rate; a later 16.7 M scan found beat-6 singletons. Fixed by the beat-6 section above.]
- The 5 old witnesses now change beats 4, 5, 6, 7 under all 16 rounds' tables.
- Lemma test: 200,000 random beat-7 changes never touch beats 0-4 and always change beat 5.
- B0 and every rehair pair: still 0 exhaustive single-input singletons for all 16 rounds' tables
  (the pair code is untouched). Bow, rehair and full-cipher inverses pass.
- Key signature: no new functions or tables. `BOW_STROKES` was already in the `mix_data`
  digest (and in the description), so key_sig and every tag changed. Closure still 57 code
  names (all in the 62-name `MIX_CODE_FUNCS`) and 35 data names.
- Tests: **222/222 passed** (219 before, plus 3 new checks; the stored "exactly 5 singletons"
  check became "0 singletons", and the bow-stroke literal check was updated to `(5,6,0)`).
  16-round bit avalanche mean 511.8/1024 (min 460, max 573).
- Previous hello-world sample (pickup `76908595dcdc8f11ff9e045ac25c080c`) fails with tag
  mismatch. Pre-change copy: `/tmp/sneak_n2_pre_beat7`.

**Honest side effects.** The bow ALONE (before rehair) now leaves more single-byte changes:
1,083/522,240 in the test scan (was 555), almost all beat 7 changes that end up in beat 5 only.
These are not singletons after the rehair (that pair then sees a one-cell change), which is the
property the design relies on. Beat 0 now feeds two pressure reads (`(6,7,0)` and `(5,6,0)`),
so beat 0 has slightly more control over the bow's rotations. The bow-local linear relation
from the attack report (cell 6 bit 0 -> cell 7 bit 4, corr about 0.04) is unchanged.
This is a fix to one local property; it is not evidence the cipher is secure.

## History — key-signature coverage gap closed (2026-11-09, superseded above for the bow)

Superseded for the bow by the beat-7 fix above. This section superseded everything below, including the keyed Latin pair notes. The
cipher arithmetic was **unchanged**. Only what `key_signature` commits to changed, so the
key signature and every tag changed. Still N2 / SN2, still homemade, **not for real secrets**.
No PNG, seed, frozen snapshot, attack folder, baseline, renderer or demo-nonce was changed.

**The gap.** `mix_code` hashed source only for a hand-picked list. `staff_mix`, `staff_unmix`,
`shell_mix`, `shell_unmix`, `weave`, `unweave`, `xor_grid`, the schedule (`Schedule`,
`StaffSponge`, `keyed_sbox`, `mat_apply`, `mat_invertible`), the block encoding, whitening and
AE wrapper were outside it. The earlier attack showed that replacing `staff_mix` with a copying
identity left key_sig unchanged.

**The fix.**
- `MIX_CODE_ROOTS = (encrypt, decrypt, siv_nonce, key_signature, split_blob)`.
- `mix_code_closure()` walks the AST of each reachable module-level function or class on every
  call, resolving `ast.Name` references in the module's current globals. A replaced function, and
  any new module-level helper it names, is therefore followed.
- `MIX_CODE_FUNCS` is now the full explicit list (62 names). That is the 57 reachable
  functions and classes plus 5 import-time table builders (`_gf_mul_raw`, `bar_det`, `bar_inv`,
  `triplet_det`, `triplet_inv`). Added: staff_mix, staff_unmix, shell_mix, shell_unmix, weave,
  unweave, xor_grid, encrypt_grid, decrypt_grid, bytes_to_grid, grid_to_bytes, encode_block,
  Schedule, StaffSponge, keyed_sbox, mat_apply, mat_invertible, staff_clef, siv_nonce, _tag,
  encrypt, decrypt, split_blob, key_signature, mix_description, mix_code_closure,
  _referenced_globals, _canon_data, _seed_bytes, load_seed, AuthError and DecodeError.
- `mix_description()` hashes, per function: name, source, and canonical `__defaults__` /
  `__kwdefaults__`, plus any extra names the live closure finds.
- New `mix_data` digest: every module-level data value the closure reaches is canonically
  encoded and hashed. There are 35 names: BARS, BARS_INV, TRIPLETS, TRIPLETS_INV, CROSS_*,
  BOW_*, LAYERS, SM4_SBOX, _GF_MUL, MIX2_MATRIX/INV, FIELD_POLY, all sizes and offsets,
  VERSION, SEED_PATH and the coverage lists themselves.
- Fails closed: unreadable source, a non-Python callable (a builtin, `functools.partial`) or
  unencodable data raises an error instead of being skipped.
- Outside coverage, and checked by a test: only `ddt_max`, `lat_max`, `grid_rows` and
  `encrypt_hello`, which are analysis and display helpers that encrypt/decrypt never reach.
- Cost: `key_signature` takes about 17 ms per call. It runs on every encrypt and decrypt.

**Verified.**
- An independent AST walk in the test finds nothing reachable that is missing.
- Independent recomputation of both digests matches.
- A behaviour-preserving modified copy of each of the 60 covered functions and classes (all
  but the two exception classes) changes key_sig, and makes live decrypt of the hello-world
  fail with AuthError "tag mismatch".
- Re-run of the copied-identity `staff_mix` demo: key_sig now differs, its blob fails live on
  **tag** (before: tag valid, then DecodeError), and the genuine hello-world fails on tag inside
  the tampered process.
- A replacement that calls a new helper puts that helper in the closure, and changing only the
  helper changes key_sig.
- Changing LAYERS, SM4_SBOX, _GF_MUL, BARS_INV, TRIPLETS_INV, MIX2_INV, NR or VERSION changes
  key_sig. None of these were covered before.
- The previous sample (pickup `24d554eb3d22f0b6412d7da59e504df1`) fails with tag mismatch.
- Tests: **218/219 passed**. The one failure is still the strict bow+rehair no-singleton test
  (5/522,240, the table-independent field-kernel cases described in the history below).
- 16-round bit avalanche: mean 511.1/1024. Ciphertext-byte chi-square: 196.9 < 330.5.

**Limits (honest).** This is source attestation of the running process, not runtime
integrity. It does not see:
- C-level or interpreter changes, or the stdlib (hashlib, hmac, os, json, inspect, ast,
  textwrap, types).
- Helpers living in another module that a foreign replacement calls. The replacement's own
  source is hashed; its foreign helpers are not.
- A swapped `__code__` whose file inspect reads differently, or edited `linecache` contents.
- Mutation of runtime-built per-message tables inside `Schedule` objects.
- An attacker who also patches `inspect` or `ast`, or replaces the attestation consistently.

Bytecode is deliberately not hashed, so signatures stay stable across Python versions.
Anyone who can run code in the process can still build their own tampered implementation.
The signature only ensures that such an implementation does not validate genuine tags.

## History — keyed Latin pair for B0 and odd rehair (2026-11-09, superseded above)

Superseded by the signature-gap fix above; kept as history. It had superseded the rotation
retune earlier the same day. Still live **N2 / SN2**, not N3, still homemade, **not for real secrets** (use
AES-GCM-SIV, age or libsodium). No PNG, seed, frozen snapshot, attack folder, baseline,
renderer or demo-nonce was changed; the picture is stale.

**Design as implemented.** B0 (bar boundary 0, pair (0,1)) and all four odd-rehair pairs
(t-1,t), t = 1,3,5,7, no longer use ARX. Each is the same keyed "Latin" pair:

```
x  = u XOR v ;  y = u XOR gf_mul(2, v)       # MIX2_MATRIX ((1,1),(1,2)), SM4 field 0x1F5
u' = S[x]    ;  v' = S2[y]                    # the CURRENT round's two keyed S-boxes
inverse: x = SI[u'], y = SI2[v'];  v = gf_mul(gf_inv(3), x XOR y);  u = x XOR v
```

`latin_pair(u, v, Sa, Sb)` / `latin_unpair(u, v, SIa, SIb)` implement it; `b0_apply/b0_unapply`
wrap it; `bar_mix(g, Sa, Sb)`, `bar_unmix(g, SIa, SIb)`, `odd_restack(staff, Sa, Sb)`,
`unodd_restack(staff, SIa, SIb)` take the tables explicitly (no defaults). `round_enc` passes
`rk["S"], rk["S2"]` to both bar passes and both rehair passes; `round_dec` passes
`rk["SI"], rk["SI2"]`. No new sponge domain was needed. The six field pairs, triplets, bow,
cross layers, schedule, encoding and AE format are unchanged.

`B0_ROT_R1/R2` and `ODD_RESTACK_R1/R2` were removed. `mix_description()` now records B0 and
odd_restack as `kind="field+keyed-sbox"`, `field=((1,1),(1,2))`,
`tables="u'=S[x];v'=S2[y];inverse SI,SI2"`. `MIX_CODE_FUNCS` gained `latin_pair`,
`latin_unpair`, `round_enc` and `round_dec`. The last two were added because the choice of
tables is made in `round_enc`/`round_dec`, so the key signature now commits to it.

**Why one-input changes cannot be singletons.** Change u alone by d: x and y both change by d.
Change v alone: x changes by d and y by gf_mul(2,d), which is nonzero. Bijective S-boxes keep both
changes, so both outputs change for any tables.

**Measured (demo schedule).**
- Exhaustive single-input singletons, 2 x 255 x 65,536 per map: B0 = **0** (pure Python, round-0
  tables) and B0 plus each rehair pair (0,1),(2,3),(4,5),(6,7) = **0** for all 16 rounds'
  tables (80 maps). Before: ARX (2,7) had 10,752.
- B0 40,000-sample one-input test: **0** (before: 9). The strict test now passes.
- Bow+rehair odd-input scan (522,240 cases): **5** singletons (before: ARX (5,4) had 3).
  0x80: **0/2,048**. The strict no-singleton test **still fails**, and it was not loosened.
  All 5 are beat-7 changes where the bow's (6,7) stroke leaves a two-cell delta with
  du = dv or du = 2dv, which is exactly the field step's kernel. They are table-independent:
  all 5 stay singletons under every round's tables (e.g. uniform staff 26, beat 7 ^ 0x24 gives
  bow delta (0x2b,0x2b) on (6,7), and only beat 7 changes).
- Exact affine output bits: **none** for any of the 16 rounds' tables (before: two LSB relations).
- (0,0) is **not** a fixed point in any round, e.g. round 0 maps it to (142,210). Each table pair
  still has 0 to 3 fixed points (u,v)->(u,v), as expected for random-like permutations.
- Old `(0,0)` vs `(5,1)` witness is no longer `(0,3)`.

**Results:** test suite **193/194 passed, 1 failed**. The one failure is the strict bow+rehair
no-singleton assertion described above. 16-round bit avalanche mean 511.1/1024 (min 449, max 570);
ciphertext-byte chi-square 230.7 < 330.5. See `test_results.txt`. The previous hello-world sample (pickup
`a287436b086c25ff762366eb747704d0`) fails with **tag mismatch**. Pre-change copy:
`/tmp/sneak_n2_pre_latin_mix`.

**Inherent leftovers:** two-input differences with du = dv or du = 2dv cancel one output of
any invertible linear 2-cell step, and keyed S-boxes after it cannot change that. The bow can
feed such a delta to pair (6,7) (5 cases above). [Closed by the beat-7 bow fix at the top: last stroke now `(5,6,0)`.]

## History — rotation retune (2026-11-09, superseded by the keyed Latin pair above)

Superseded the same day by the keyed Latin pair; kept as history. Was live
**N2 / SN2**, not N3, still homemade, **not for real secrets** (use AES-GCM-SIV, age or
libsodium). Only four constants changed; the ARX formula
`u'=(u+rotl8(v,r1))&255; v'=v^rotl8(u',r2)` is unchanged. No PNG, seed, frozen
snapshot, attack folder, renderer or demo-nonce was changed; the picture is stale.

| Layer | Before | After | r1+r2 mod 8 |
|---|---|---|---|
| B0 ARX (`B0_ROT_R1`, `B0_ROT_R2`) | 3, 5 | **2, 7** | 0 -> 1 |
| Odd-beat rehair (`ODD_RESTACK_R1`, `ODD_RESTACK_R2`) | 2, 6 | **5, 4** | 0 -> 1 |

**How chosen (exhaustive over all 49 pairs in 1..7):**

- B0: single-input singletons over all 255 x 65,536 changes in each input depend only
  on `(r1+r2) mod 8`: 0 -> 2,173,952; 4 -> 205,312; 2 or 6 -> 52,224; 3 or 5 -> 46,080;
  **1 or 7 -> 10,752** (minimum). A u-only change is never a singleton for any pair.
  **Zero is impossible in this ARX form:** a v-change of `0xFF` is rotation-invariant,
  and with u in {0,128} the sum changes by exactly `0xFF`, which cancels in v' for every
  rotation choice. Among the 12 minimum pairs, (2,7) had the fewest hits (9) in the
  test's seeded 40,000-sample protocol and shares no value with the rehair pair.
  The u=0 row is no longer constant: v' takes 128 values (was 1). `b0_apply(0,1)=(4,3)`.
- Odd rehair: bow+rehair odd-input singletons with the test protocol (256 uniform +
  256 seeded staffs, 4 odd beats, all 255 deltas = 522,240 cases). Sum 0 pairs gave
  129..171; (2,6) gave 150 (7/2,048 high-bit). **(5,4) gave 3** (minimum; next 4) and
  **0/2,048** for delta 0x80; even-beat singletons 0. No pair reached 0.

**Exact single-bit routings left** (only the carry-free LSB of the addition, verified on
all 65,536 pairs): B0 `u'_0 = u_0 ^ v_6`, `v'_7 = u_0 ^ v_6 ^ v_7`; rehair
`u'_0 = u_0 ^ v_3`, `v'_4 = u_0 ^ v_3 ^ v_4`. No output bit now equals a single input bit
(previously B0 `v'_5 = u_0` and rehair `v'_6 = u_0`).

**Results:** test suite **188/190 passed, 2 failed**. The two failures are the deliberately
strict no-singleton assertions, left unweakened: B0 still has 9/40,000 sampled singletons
(10,752 exhaustive, e.g. `(0,0)` vs `(0,0xFF)` gives `(0,0)` vs `(0xFF,0)`), and bow+rehair
still has 3/522,240 (all-zero staff, beat 3/5/7 flipped by `0xFF` leaves only beat 0/2/4
changed by `0xFF`). The old `(0,0)` vs `(5,1)` witness now XORs to `(0x09,0x85)`.
`mix_description()` and the key signature changed; the previous hello-world sample
(pickup `724da1f4...`) fails as **tag mismatch**. New hello-world: pickup
`a287436b086c25ff762366eb747704d0`, nonce `df0f7538e837990acef5d7564b4ab2fb`, decrypts to
`b'hello world'`. Pre-change copy: `/tmp/sneak_n2_pre_rotation_retune`.

## Previous revision — four requested leftover-shape changes (2026-11-08)

Superseded on 2026-11-09 by the rotation retune above; kept as history. This was live **N2 / SN2**,
not N3, and is still a homemade 1024-bit block cipher, **not for real secrets**.
No PNG, seed, frozen snapshot, attack report, renderer or demo-nonce was changed.
The picture is stale; `demo-nonce.txt` is NOT the new hello-world sample's nonce.

**Important verification finding:** the prescribed ARX formulas and rotations were
implemented exactly, but two promised properties are false. Tests deliberately
retain the intended no-singleton assertions; they are not weakened to hide this.
B0 `(0,0)` vs `(0,1)` outputs `(0,0)` vs `(8,0)`, so a one-input difference
can still leave only one changed output. With `r1+r2=8`, at `u=0` we have
`rotl8(rotl8(v,3),5)=v`, hence B0's second output is zero for every v.
The odd rehair `(2,6)` has the analogous rotation cancellation. At a zero staff,
changing input beat 3 by `0x55` leaves just beat 1 changed after bow, and just
beat 0 changed after bow+rehair. Thus these four edits must **not** be described
as four successfully closed issues. No unrequested extra ARX step or alternate
rotation choice was added. See `test_results.txt` for the full verification.

### Unchanged format, API and authentication

- Layout remains **195 bytes**: `SN2 || pickup(16) || nonce(16) || ct(128) || tag(32)`.
  Offsets are `[3:19]`, `[19:35]`, `[35:163]`, `[163:195]`. Payload max is 127 bytes.
- `encrypt(msg, seed=None, nonce=None)` has no new public arguments. Pickup is
  fresh `os.urandom(16)`; nonce is `SHA-256(clef || pickup || encode_block(msg))[:16]`.
  Clef remains `StaffSponge(b"C", seed, bytes(16)).take(16)`.
- `key_sig = StaffSponge(b"G", seed, mix_description()).take(16)` is unchanged.
  Tag is `HMAC-SHA256(mac_key, clef || key_sig || SN2 || pickup || nonce || ct)`.
  Length, prefix and tag are checked before decryption; SIV is checked after decode.
  The pre-change 195-byte sample fails on **tag**; old 179-byte samples fail on **length**.
- State remains 16 faces × 8 byte-beats, 16 rounds, final whitening, two keyed
  SM4-affine S-box colorings, original schedule, weave, butterfly and shell bridges.
  No AES wrapper, new public version, or new attack campaign was introduced.

### 1. Fourth cross-staff layer

Each cross pass copies the grid and rows and mixes matching beats `t=0..7`
with the existing SM4-field `mix2`, always lower staff index first:

1. Opposite: `(0,4),(1,5),(2,6),(3,7),(8,12),(9,13),(10,14),(11,15)`.
2. Radial: `(0,8),(1,9),(2,10),(3,11),(4,12),(5,13),(6,14),(7,15)`.
3. Adjacent: `(0,1),(2,3),(4,5),(6,7),(8,9),(10,11),(12,13),(14,15)`.
4. **CROSS_BRIDGE:** `(1,2),(5,6),(9,10),(13,14)`.

The first three are perfect matchings; the fourth intentionally covers only eight
staffs. Their union now has **one connected 16-staff component**, joining the
previous two groups `{0,1,4,5,8,9,12,13}` and `{2,3,6,7,10,11,14,15}`.
Invert all four layers in reverse order using `mix2_inv`; input is never mutated.
Graph connectivity is not a proof that every differential spreads to every staff.
`mix2(u,v)=(u XOR v,u XOR gf_mul(2,v))` remains over SM4 GF(2^8), polynomial
**0x1F5**, determinant 3; inverse is `gf_inv(3)` times `((2,1),(1,1))`.

### 2. Nonlinear B0 only

B0 remains first in BARS on pair `(0,1)`, with `B0_ROT_R1=2`, `B0_ROT_R2=7` (were 3, 5 on 2026-11-08).
Its historical matrix slot is retained for names/order/history but is **not used**
by bar_mix/bar_unmix and is **not described as its active operation** in JSON.

```
u' = (u + rotl8(v,2)) & 255
v' = v XOR rotl8(u',7)
v  = v' XOR rotl8(u',7)       # inverse first
u  = (u' - rotl8(v,2)) & 255
```

B1, M2, B2, M3, B3 and B4 retain their field matrices. Both bar passes use the
same nonlinear B0. All six triplets remain exactly **Z/256Z** with unchanged
helpers/tables. The old `(0,0)` vs `(5,1)` witness now gives output XOR
**`(0x09,0x85)`** with (2,7) (was `(0x0d,0xa0)` with 3,5), not `(0,3)`, and that differential is no longer base-independent.
This does not imply all cancellation is gone: the counterexample above remains.

### 3. Odd-beat rehair

After **each bow and before each cross pass**, copy each staff and apply the same
ARX pair formula with `ODD_RESTACK_R1=5`, `ODD_RESTACK_R2=4` (were 2, 6 on 2026-11-08), on pairs
`(0,1),(2,3),(4,5),(6,7)` in this order. `unodd_restack` undoes odd beats
`7,5,3,1`, XORing back v before subtracting from u. No third pressure cell;
beat 7 mixes only with beat 6, never beat 0. Bow itself remained unchanged at the time
(since the 2026-11-09 beat-7 fix the last stroke is `(5,6,0)`, see top):
`(0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,7)` with rotations
`1+p%7`, `1+(p>>3)%7`. Only the pressure read, not a mixed pair, may wrap.
Bow+rehair still has sampled odd-input singleton counterexamples, as noted above.

### 4. Listed mix-code commitment

`mix_description()` is recomputed canonical ASCII JSON (`sort_keys=True`, compact
separators). It describes the active B0 as kind ARX/pair/r1/r2 (not its old matrix),
other pair matrices, integer triplets, field mix2, bow, rehair, all four cross
matchings/effective order and placements, plus a SHA-256 source digest.

`MIX_CODE_FUNCS` is an ordered tuple of **function names resolved dynamically**.
For each name, hash its UTF-8 name followed by `inspect.getsource(globals()[name])`
in UTF-8; each part is prefixed by its 8-byte unsigned big-endian byte length.
The digest is recorded as lowercase hex, along with the function list and framing.
Source is not cached; unavailable source raises rather than silently omitting it.
This intentionally does **not** hash the entire file.

Listed functions: bar_mix/bar_unmix; triplet_mix/triplet_unmix/triplet_apply/
triplet_det/triplet_inv; bow_pressure/unbow_pressure/bow_stroke/unbow_stroke;
rotl8; cross_staff_mix/cross_staff_unmix; odd_restack/unodd_restack;
b0_apply/b0_unapply; mix2/mix2_inv; bar_apply/bar_inv/bar_det;
gf_mul/gf_inv/_gf_mul_raw.

A copied bar_mix that skips B0 while BARS stays identical changes the description
and key signature; its alternate valid blob fails live authentication on **tag**,
not DecodeError. Replacing a listed runtime function object is also detected.
This is stronger source attestation, **not runtime integrity**: omitted helpers,
cached tables, equivalent rewrites inspect does not see as those objects, or
changes to unlisted callers can still evade it. It is not a security proof.

### Actual round order

Forward: XOR rk → S → weave → field butterfly → field bridges → bar_mix
(nonlinear B0, six field pairs) → triplet_mix → bow_pressure → **odd_restack** →
**cross_staff_mix (four layers)** → S2 → encore bar_mix → encore triplet_mix →
encore bow_pressure → **odd_restack** → **cross_staff_mix (four layers)**.

Inverse (first statement remains cross_staff_unmix): **uncross → unodd_restack →
unbow** → encore untriplets → encore unbars → SI2 → **uncross → unodd_restack →
unbow** → mid untriplets → mid unbars → unbridges → unbutterfly → unweave → SI → XOR rk.

### Completed verification result

Full suite completed: **181/183 passed, 2 failed**, with no flake or rerun.
Ciphertext-byte chi-square was **261.9 < 330.5**; all statistical thresholds
were retained and passed. Both failures are deterministic counterexamples to the
requested spreading properties, not inverse/authentication failures:

- B0 one-input scan: **2,609 / 40,000** derivatives changed only one output.
  Old `(5,1)` differential has **30 distinct output XORs** across all 65,536 bases,
  none wiping either output; so the old named witness is gone, not all singletons.
- Odd-input scan, 256 uniform + 256 seeded random staffs × 4 odd beats × all
  255 deltas: bow alone **555 / 522,240** singletons; bow+rehair still
  **150 / 522,240**. For delta **0x80** alone: **9 / 2,048 → 7 / 2,048**.
  Explicit 0x80 counterexample: input `[0xc0]*8`, flip beat 3; bow+rehair outputs
  `[200,13,44,52,216,28,116,165]` and `[192,13,44,52,216,28,116,165]`.

All field/B0/bow/rehair/cross/round/full-cipher inverses, connected graph,
parameter and copied-code attestation, exact forward/reverse order, old sample
rejections, and protected baselines passed. The source SHA-256 is
`991ae8f61ee53ec899003b57bc143d70dc9fcdb37de6bd2b334a18f020ebdf5f`.
New hello-world: pickup `724da1f42b3aa81489b97a1dcaeb14c4`, nonce
`4c6c2d12c72419fcb721e2d2aad9800c`, 195 bytes; independently verified formula,
plaintext `b'hello world'`, and fresh encryption differs.
The protected manifest contains **663 unchanged files** (including all non-target
live-tree files, the frozen trees, attack folders, PNGs, seed, demo-nonce and renderer).
The exact prescribed changes remain applied, with failures visible; this is **not**
a clean all-tests-passing claim and no additional redesign was attempted.

### Verification and remaining limits

Run `python3 -B test_sneak_n2.py > test_results.txt`; no statistical threshold was
loosened. The suite includes the intended two-sided inverses, 1,000 cross-grid
inverses, parameter/source commitment, explicit/instrumented order, historical
blob rejection, odd-beat delta scans including 0x80, tamper checks, statistical
bounds, and frozen-tree baselines. Any false intended property remains a failing
assertion, not a passed test obtained by changing its meaning.

The `(0,0)` ARX fixed point remains. Other linear field pairs can still cancel at
the mix; triplets are still integer. Anyone holding the seed can decrypt. Linear,
algebraic, slide and related-nonce attacks remain untested on this revision.
Python lookup timing and single-block limits remain. Measurements are not a
security proof. **Use AES-GCM-SIV, age or libsodium for real secrets.**

Backup: `/tmp/sneak_n2_pre_four_leftovers` (full pre-edit live tree minus `__pycache__`).
Only sneak_n2.py, test_sneak_n2.py, SPEC.md, README.md, hello-world.txt and
 test_results.txt were edited. Frozen/attack files, both live PNG copies, seed,
`demo-nonce.txt` and `render_n2.py` remain untouched.

# Historical appendix — superseded revisions

Everything below describes earlier revisions, including text formerly labelled
"current". The live formulas/order/limits are exclusively the section above.

# Sneak staff-core N2: specification (8-bit cells; seven pair mixes + six triplets per pass)

## Current change — random pickup / anacrusis (2026-11-08)

Encryption is no longer deterministic. Each `encrypt` call draws a fresh **16-byte pickup** with `os.urandom(16)` (the anacrusis before the downbeat). It is used only for the pickup, never for the nonce.

- **Blob (195 bytes):** `b"SN2" ‖ pickup(16) ‖ nonce(16) ‖ ct(128) ‖ tag(32)`; offsets: pickup `[3:19]`, nonce `[19:35]`, ct `[35:163]`, tag `[163:195]`. 1,560 bits.
- **Nonce:** `SHA-256(clef ‖ pickup ‖ encode_block(msg))[:16]`; clef unchanged (seed-only, not stored).
- **Tag:** `HMAC-SHA256(mac_key, clef ‖ "SN2" ‖ pickup ‖ nonce ‖ ct)`, checked first with `compare_digest`.
- **Decrypt:** length must be exactly 195 (old 179-byte blobs → `AuthError` on length), version, tag (binds the pickup), decrypt, decode, then recheck `nonce == SHA-256(clef ‖ pickup ‖ encode_block(msg))[:16]` → `AuthError` on mismatch.
- **API:** `encrypt(msg, seed=None, nonce=None)` has **no public `pickup=` argument** (passing a target's pickup back in would rebuild the dictionary attack). A supplied `nonce` is checked against the synthetic nonce for the fresh pickup and almost always raises `ValueError`. `siv_nonce(msg, pickup, seed)` now needs the pickup.
- **Demo:** hello-world pickup `8b9291ce06eaf92767cfa2c89d68b639`, nonce `4ea3cefffeabc7257c7f26181a63f08a` (one random sample; see `hello-world.txt`). Decrypts to `b'hello world'`. `demo-nonce.txt` still holds the old pre-pickup nonce and is used only as a fixed test schedule nonce. `sneak-staff-n2.png` was **not** regenerated and is stale.
- **Unchanged:** BARS, TRIPLETS, mix2, S-boxes, schedule, clef derivation, encoding, `SN2` magic, 16 rounds.

**Honest leftovers:**
- This stops the public `encrypt(guess) == blob` PIN match. Anyone who has the seed and reimplements the cipher can still test guesses using the pickup copied from the target blob.
- Triplets and mix2/butterfly/bridges remain integer mixes with isolated even-coefficient high-bit behavior.
- Field-linear multi-input cancellations remain on the named pairs.
- No key signature: mix tables are still not committed in the tag. Old 179-byte blobs (pre-pickup, pre-field-retune, pre-triplet, pre-join, testn3) now fail because the **length** changed, not because the mixes are named in the MAC.
- Still homemade and **not for real secrets**. Use AES-GCM-SIV, age, or libsodium.

Sections below describe earlier revisions where they mention a 179-byte blob, deterministic SIV, or 1,432 bit flips.


## Current field retune (2026-11-08)

Only the seven named pair arithmetic operations were retuned, including their encore. Coefficient tuples, identities, application order and open-staff boundaries are unchanged. Pair multiplication uses GF(2^8) with the SM4 irreducible polynomial x^8+x^7+x^6+x^5+x^4+x^2+1 = **0x1F5**, reduction constant **0xF5**, not AES's polynomial and **not AES MixColumns**. The standard SM4 S-box table and its affine layers are unchanged.

For M=((a,b),(c,d)), bar_apply returns (a⊗u XOR b⊗v, c⊗u XOR d⊗v). det=(a⊗d) XOR (b⊗c); the inverse is det⁻¹⊗((d,b),(c,a)).

| Name | Pair | Unchanged matrix | Field det |
|---|---|---|---|
| B0 start | (0,1) | ((1,5),(1,6)) | 3 |
| B1 bar 2 | (1,2) | ((1,1),(1,2)) | 3 |
| M2 beats 3-4 | (2,3) | ((3,5),(1,2)) | 3 |
| B2 center | (3,4) | ((1,3),(1,4)) | 7 |
| M3 beats 5-6 | (4,5) | ((5,2),(2,1)) | 1 |
| B3 bar 6 | (5,6) | ((2,1),(1,1)) | 3 |
| B4 end | (6,7) | ((3,1),(2,1)) | 1 |

Correction to the proposed determinant list: M2 is **3**, not 10: (3⊗2) XOR (5⊗1) = 6 XOR 5 = 3. These degree-low products need no polynomial reduction. Coefficients were not changed.

All nonzero single-cell XOR differences affect both outputs of every pair, at every base state: all four coefficients are nonzero field elements. Tests exhaust the derivatives and multiplication XOR-linearity, and all 65,536 inverse inputs per matrix. Triplets remain exactly Z/256Z determinant-1 mixes; mix2, butterfly and bridges remain Z/256Z. The combined field-pair/integer-triplet layer is NOT a single linear matrix over either ring; old parity-column proofs and weights below apply only to the historical pre-retune revision. Current combined/encore 0x80 checks cover zero and all 256 uniform base states, not a proof for every possible nonuniform base.

(Historical, field-retune revision) Blob was **179 bytes**, SN2 || nonce(16) || ct(128) || tag(32). No pickup, randomness, key-signature commitment, nonce/MAC change or N3 was added. Hello-world nonce remains b98b9c3815374fac6048ec47c9760eb3. Decryption still undoes encore triplets before encore bars, S2, mid triplets and mid bars.

**PNG is stale:** no PNG was regenerated or touched; use hello-world.txt for the new ciphertext/grid. Historical descriptions and measurements below are superseded for named-pair arithmetic by this section.

**Leftovers:** deterministic PIN dictionary matching still works; pre-field-retune/pre-triplet/pre-join/testn3 tags still verify and old demo blobs fail closed as DecodeError or AuthError, not universal version rejection. Integer helpers retain isolated even-coefficient high-bit behavior. Field-linear mixes still permit multi-input cancellation. These are layer-level properties, not full-cipher security. Homemade, not for real secrets.


> **Historical change — triplets only (2026-11-08):** six overlapping det-1 3×3 mixes over Z/256Z now follow each bar pass, including the encore. Seven named pair matrices stay unchanged. See §11 for matrices, the exact single-cell-difference proof and composite high-bit measurements. No PNG, seed, named snapshot, attack folder, nonce/MAC formula or blob format was changed. PIN guessing and same-version old-blob tags remain known leftovers. Historical tables below do not measure this revision.

> **WARNING:** N2 is a **homemade, unreviewed scheme**. Nobody but its author has analyzed the block cipher. It is *authenticated*, because an HMAC-SHA256 tag is checked before anything is decrypted, but the cipher underneath is an art-and-puzzle SPN. **Do not use it for real secrets.** For anything that matters use **AES-GCM-SIV (RFC 8452), age, or libsodium**.

**Files** (all in `/workspace/sneak_n2/`):
- `sneak_n2.py`: the library.
- `test_sneak_n2.py`: the tests, with output in `test_results.txt`.
- `sm4_vector_check.py`: a reference SM4 used **only by the tests** to authenticate the S-box table against published vectors. N2 does not use SM4 itself.
- `render_n2.py`: writes `hello-world.txt`, `sneak-staff-n2.png` and `/workspace/sneak-staff-n2.png`.
- `demo-nonce.txt`: the frozen demo nonce.
- `baselines/`: sha256 lists of the frozen trees.
- `attacks/`: the attack pass on the **first, 4-bit** N2. It is still the 4-bit report: it was **not** re-run on any later version, including the 8-bit cells, the bar-line layer and second coloring. Its numbers describe 4-bit nibbles, PRESENT-affine S-boxes and a mod-16 mix, not the current cipher. It is left untouched as a snapshot.

**Change log (all 2026-11-08, version tag stays `SN2`):**
1. **First N2:** 16 × 8 nibbles, 64-byte block, 115-byte blob. This is the version attacked in `attacks/`.
2. **Staff loop added**, then **metered staffs** (203-byte blob), then **unlooped**.
3. **Reverted** to 16 × 8 nibbles, unlooped. This was functionally the first N2 again.
4. **8-bit cells:** every beat is now one **byte** instead of a nibble.
   - **S-box:** 8-bit and keyed, built as an affine map around the published SM4 S-box.
   - **Mix:** the same two-cell mix, now mod 256.
   - **Sizes:** a 1024-bit (128-byte) block, a 179-byte blob, and a maximum payload of 127 bytes.
   - **Unchanged:** the layout (16 faces × 8 open beats, two measures of 4/4, no loop), the weave, the 1:1 bridges, the SHA-256 schedule, 16 rounds, whitening, the tag-first decrypt, the seed file and the demo nonce.
   - **Old blobs:** 115-byte 4-bit blobs and 203-byte metered blobs fail closed at the length check (`AuthError`). This is tested.
5. **Five bar-line mixes (historical step):** each 8-beat staff is read as **four measures of 2/4** between **five bar lines**, at beat boundaries 0, 2, 4, 6 and 8. Every bar line performs a **different** invertible 2-byte mix, applied each round after the shell bridges (§4, §5).
   - Format, sizes and everything else are unchanged.
   - Ciphertexts changed, and the demo was re-encrypted with the same nonce.
   - At this historical step the pre-bar demo still passed the old tag, then failed decoding. Since the later clef change, those pre-clef blobs fail authentication instead.

6. **Late coloring, clef, encore and SIV:** described below; earlier tables are historical.
7. **Interior joins:** M2 and M3 complete the seven adjacent pair mixes, without wrapping.
8. **Triplets (current):** six overlapping determinant-1 3×3 matrices immediately after each bar pass, including the encore (§11).

**What is homemade and what is not:**
- **Homemade:** the whole 1024-bit block cipher. That covers the dual-octahedra layout, the affine keying of the S-boxes, the face-beat weave, the staff butterflies and shell bridges built from the two-cell mix `(u+v, u+2v) mod 256`, the seven pair mixes, six overlapping triplets per pass, and the round structure.
- **Standard parts:**
  - SHA-256 as the one-way expander (the "staff sponge"),
  - HMAC-SHA256 as the integrity tag,
  - the **published SM4 (SMS4) S-box table** as the base of the keyed S-boxes.
- **Not used anywhere:** AES, the AES S-box table, MixColumns, AES-GCM, or the `cryptography` package. A test scans the library for these.
- **An honest caveat on "not AES":** the SM4 S-box, like the AES S-box (and Camellia's and ARIA's), is built from inversion in GF(2^8) wrapped in affine maps. All such boxes lie in the **same affine-equivalence class**, which is exactly why they share DDT max 4 and nonlinearity 112. We checked this: SM4's DDT spectrum is identical to that of plain GF(2^8) inversion (computed with a non-AES polynomial). So N2 uses no AES component, but its S-box class is the well-studied "inversion" class, not something new.

## 1. State, key, blob
- **State:** 1024 bits = 16 faces × 8 beats × **8-bit cells**.
  - Faces 0–7 are the **inner** octahedron (`inner 1–8`) and faces 8–15 the **outer** one (`o1–o8`).
  - `g[f][t]` is the byte at face f, beat t, and block byte 8f + t is face f, beat t.
  - Each staff has 8 beats, read as four measures of 2/4 between five bar lines B0–B4. It is an open line: beat 1 and beat 8 are its two ends, not neighbours.
- **Seed:** `/workspace/sneak1024-seed.txt` (256 hex digits = 1024 bits), the same file and parse as N1, taken as 128 bytes.
- **Nonce (homemade SIV-style):** `nonce = SHA-256(clef ‖ encode_block(msg))[:16]`, computed by `encrypt`; there is no `os.urandom` default. A caller-supplied `nonce=` that differs from this value raises `ValueError`.
- **Encoding:** `bytes([len]) + msg + zeros`, 128 bytes in total, so **`len ≤ 127`**. Larger messages are rejected.
- **Blob:** `b"SN2" ‖ nonce(16) ‖ ct(128) ‖ tag(32)`, **179 bytes** in total.
  - `tag = HMAC-SHA256(mac_key, clef ‖ b"SN2" ‖ nonce ‖ ct)`, with `clef = StaffSponge(b"C", seed, bytes(16)).take(16)` (seed-only, zero nonce as concert pitch; never stored in the blob).

## 2. Staff sponge (key schedule)
```
stream(domain) = SHA-256("SN2/" ‖ domain ‖ ctr32 ‖ seed ‖ nonce) for ctr = 0, 1, 2, …
mac_key  = first 32 bytes of stream("M")
schedule = stream("K"), consumed in order:
  for r = 0..15:  rk_r (128 bytes as a 16×8 byte grid)
                  A1, A2: invertible 8×8 GF(2) matrices (8 byte rows each, resampled until GF(2) rank is 8)
                  b1, b2: one byte each
                  SH[16] ∈ 0..7, SV[8] ∈ 0..15
                  σ_f, a permutation of 8 beats for each of 16 faces
                  bridge, a permutation of 64 (inner cell c ↔ outer cell bridge[c])
                  A3, A4: resample invertible 8×8 GF(2) matrices; b3, b4: one byte each
                  S2, SI2 = keyed_sbox(A3,b3,A4,b4); resample these parameters if S2 == S
  white (128 bytes)
```
- Bounded integers are drawn by byte rejection sampling (no bias), and permutations by Fisher–Yates.
- **One-way:** every schedule byte is a SHA-256 output over `seed ‖ nonce`. This closes N1's linear, invertible schedule. Preimage resistance beyond SHA-256's is not claimed and cannot be unit-tested.
- **Historical bar-lines-only measurement:** a 1-bit nonce flip changes **49.96%** of the 17,408 round-key and whitening bits on average (min 48.99%, max 50.97%, over all 128 nonce bits). It also changes every round's S-box, weave, σ and bridge, and the MAC key. A seed-bit flip also gives about 50%.
- **Domain separation:** the MAC key comes from `M` and the cipher material from `K`, and the MAC key never appears in the schedule (tested).

## 3. Keyed 8-bit S-boxes
- **Base:** the **SM4 (SMS4) S-box**.
  - **Source:** GB/T 32907-2016, as printed in draft-ribose-cfrg-sm4-10 §6.2.3 (Tse, Wong, Saarinen; IRTF CFRG, 2018). The same table appears in the original 2006 SMS4 publication (Diffie and Ledin's English translation, ePrint 2008/329).
  - **Authenticated by test:** a reference SM4 built on the table reproduces GB/T 32907-2016 Example 1 (`681edf34d206965e86b3e94f536e4246`) and the draft's Example 4 (`f766678f13f01adeac1b3ea955adb594`). `S(0xEF) = 0x84`, matching the draft's worked example.
- **Construction, per round:** `S_r(x) = A2 · SM4(A1 · x ⊕ b1) ⊕ b2` over GF(2)^8. It is applied to all 128 cells.
- **Late second coloring:** `S2_r(x) = A4 · SM4(A3 · x ⊕ b3) ⊕ b4`, also on all 128 cells, **after the mid-round bars and triplets**. Its inverse `SI2` follows inverse encore triplets and bars, and precedes inverse mid-round triplets and bars. Both maps and all four matrices/offsets are stored in the round dictionary. Fresh parameters come from the same `K` stream after the bridge; round 0 retains all earlier prefixes, later rounds and whitening shift. This is separately derived keying, not independent entropy or a different algebraic S-box family.
- Both colorings are affine-equivalent to SM4: identical DDT/LAT spectra, DDT max 4 and LAT max bias 16. An additional nonlinear layer is not a proof of improved security; adjacent round boundaries may combine local maps.
- **Measured (test_results.txt):**

| Box | Permutation | DDT max | Best differential probability | LAT max \|#−128\| | Linear bias | Nonlinearity |
|---|---|---|---|---|---|---|
| SM4 base | yes | **4** | 4/256 = 2⁻⁶ | **16** | 16/256 = 2⁻⁴ | 112 |
| 32 keyed boxes (two per round, demo nonce) | yes, with correct inverse | **4** (all 32) | 2⁻⁶ | **16** (all 32) | 2⁻⁴ | 112 |
| 160 keyed boxes (5 random nonces) | yes | ≤ 4 | | | | |

- Affine equivalence preserves the DDT and LAT spectra exactly, so every round box inherits the base's bounds, as the measurements confirm.
- The 16 demo boxes are all distinct, and none equals the SM4 base.

**Why 8-bit helps:**

| | 4-bit N2 (PRESENT-affine) | 8-bit N2 (SM4-affine) |
|---|---|---|
| Best differential through one active S-box | 4/16 = **2⁻²** | 4/256 = **2⁻⁶** |
| Best linear bias through one active S-box | 4/16 = 2⁻² | 16/256 = **2⁻⁴** |
| S-boxes per round | 128 (nibbles) | 256 (bytes: two layers) |
| Block | 512 bits | 1024 bits |

- A trail with k active S-boxes has probability at most 2⁻²ᵏ in 4-bit N2 but 2⁻⁶ᵏ in 8-bit N2. For the same count of active boxes that is 3× more "bits of cost" per box, and roughly 2× more per linear-bias box (piling-up).
- This is the main margin improvement. Nobody has counted active S-boxes for either version, so no concrete bound is claimed.

## 4. Mix layers (on bytes)
**Two-cell mix** (the user's original from test1), now **mod 256**:
```
mix2(u, v)    = (u + v,  u + 2v) mod 256       matrix [[1,1],[1,2]], det = 1 (a unit mod 256)
mix2⁻¹(a, b)  = (2a − b, b − a)  mod 256
```
Tested exhaustively bijective on all 65,536 byte pairs.

**Staffs are linear (unlooped).** There is no end-to-end loop layer; the library has none, and neither do `round_enc` or `round_dec` (tested).

**Staff butterfly (within each face):** three layers m = 1, 2, 4 pair `σ_f[i]` with `σ_f[i|m]` for i with `i & m = 0`. That is 4 pairs per layer, 192 byte mix2 calls per round, and every byte of a face reaches all 8 bytes of that face.

**Shell bridges (1:1):** 64 disjoint pairs, inner cell c ↔ outer cell `bridge[c]`, both shells mixed every round. The "u" side alternates by round.

**Weave:** rotate face f by `SH[f]` beats, then rotate each beat column across the 16 faces by `SV[b]`.

**Pair layer (five bar lines plus two interior joins, seven mixes per staff per pass):**
```
staff:   B0 | b1 b2 | B1 | b3 b4 | B2 | b5 b6 | B3 | b7 b8 | B4          (four measures of 2/4)
bar  boundary  pair (0-based beats)  matrix [[a,b],[c,d]]  map (u,v) ->        det  inverse mod 256
B0   0 start   (0,1)  first measure  [[1,5],[1,6]]         (u+5v,  u+6v)        1    [[6,-5],[-1,1]]
B1   2         (1,2)  across bar     [[1,1],[1,2]]         (u+v,   u+2v)        1    [[2,-1],[-1,1]]
M2   (3)       (2,3)  interior join  [[3,5],[1,2]]         (3u+5v, u+2v)        1    [[2,-5],[-1,3]]
B2   4 center  (3,4)  across bar     [[1,3],[1,4]]         (u+3v,  u+4v)        1    [[4,-3],[-1,1]]
M3   (5)       (4,5)  interior join  [[5,2],[2,1]]         (5u+2v, 2u+v)        1    [[1,-2],[-2,5]]
B3   6         (5,6)  across bar     [[2,1],[1,1]]         (2u+v,  u+v)         1    [[1,-1],[-1,2]]
B4   8 end     (6,7)  last measure   [[3,1],[2,1]]         (3u+v,  2u+v)        1    [[1,-1],[-2,3]]
```
- These are the recommended matrices, unchanged. All seven are different, and each has det 1 (odd, so invertible mod 256).
- They are applied **B0, B1, M2, B2, M3, B3, B4** on each staff. Adjacent pairs overlap, so order matters. Decryption reverses that sequence after undoing the triplets.
- **No end-to-end loop:** beat 8 is never paired with beat 1, and the staffs stay open.
- **Tested:** each of the seven pair mixes is a bijection on all 65,536 byte pairs and its inverse undoes it; the whole bar layer inverts; it is wired into `round_enc` and `round_dec`; and no bar pairs (7, 0).
- **Historical placement experiment (before S2/encore/joins/triplets):** both placements allowed by the design were measured on identical inputs (1,500 samples, keyed rounds, no whitening). Placing the bars *before* the bridges, right after the butterfly, made early rounds slightly **worse** than having no bars at all: the 1-round mean was 53.6 vs 55.7 bits, and the 2-round mean 415.3 vs 422.6 bits. That happens because two linear within-staff layers back to back partly cancel, much as the old staff loop did. Placing them *after* the bridges re-spreads each staff's freshly bridged cells and was clearly better (§7), so that is the chosen order.

**What the bar layer is and is not (honest):**
- It is **seven different linear maps** over Z/256. Composed with the linear butterfly and bridges, the whole mixing stage is still one linear map per round, so linear layers can partly cancel each other, as the measurement above showed for the other placement.
- **Both S-box colorings break the mixes’ bit-plane structure.** Modular addition also has Boolean carry nonlinearity; these mixes are linear over Z/256, not over GF(2) on all bits. The bar matrices also keep the bit-plane structure of every mod-256 mix: carries go only upward, the LSB plane is GF(2)-linear, and 0x80-type differences pass with probability 1 (for example B4 maps (0x80, 0) to (0x80, 0)).
- The bar layer adds **structural diversity and faster cell-level spread**. It is **not a security proof**, and it adds no nonlinearity.

**The mix is still partly linear (honest):**
- **Carries only move upward.** Bit k of `u+v` or `u+2v` depends only on bits 0…k of the inputs. So the mix is "triangular" over bit-planes: high bits never affect low bits inside a mix.
- **The least significant bit-plane is exactly GF(2)-linear:** `lsb(u+v) = lsb u ⊕ lsb v`, and `lsb(u+2v) = lsb u`.
- **Power-of-two planes stay structured.** A difference of `0x80` (msb only) passes mix2 with probability 1: (0x80, 0) → (0x80, 0x80) and (0, 0x80) → (0x80, 0). More generally, low-weight differences in the high planes propagate deterministically or with high probability.
- **Only the S-boxes break these structures.** Moving from mod 16 to mod 256 adds more carry nonlinearity in the middle planes, but it does **not** remove the linear LSB plane or the deterministic msb differences.
- **Branch number:** the mix's branch number is 2, the same as before.

## 5. Round function (16 rounds)
```
round r:  g ^= rk_r                      (all 128 bytes)
          g  = S_r[g]                    (keyed 8-bit S-box on all 128 bytes)
          g  = weave(g, SH_r, SV_r)      (rotate faces, then beat columns)
          g  = staff_butterfly(g, σ_r)   (byte mix2 within each open 8-beat staff)
          g  = shell_bridges(g, bridge_r, r)   (64 inner ↔ 64 outer, 1:1)
          g  = bar_lines(g)              (B0,B1,M2,B2,M3,B3,B4: seven different det-1 byte mixes per staff)
          g  = triplet_mix(g)             (T0..T5, six adjacent overlapping triples per staff)
          g  = S2_r[g]                   (late second coloring on all 128 bytes)
          g  = same 7 pair mixes again    (bar-line encore)
          g  = triplet_mix(g)             (triplet encore: separates S2_r and S_{r+1})
after round 15:  g ^= white
```
Decryption runs the inverse layers in reverse order (encore triplets⁻¹ first, then encore bars⁻¹, SI2, mid-round triplets⁻¹, mid-round bars⁻¹ in reverse pair order, bridges⁻¹, butterfly⁻¹, unweave, S⁻¹, ⊕ key), with the schedule regenerated from seed and nonce. Every round and the full cipher are tested to invert.

## 6. Decrypt order (tag first)
1. Reject the blob unless its length is exactly **195** bytes (was 179 before the pickup). Old 115-byte (4-bit) and 203-byte (metered) blobs stop here.
2. Reject it unless the prefix is `SN2` (`compare_digest`).
3. Derive `mac_key`, recompute the tag and compare it with `hmac.compare_digest`. On mismatch raise `AuthError`, with **no decryption and no payload**.
4. Only after the tag verifies, decrypt the block. As a secondary sanity check it requires `len ≤ 127` and zero padding (`DecodeError`).
5. Recompute the SIV nonce from the recovered message; mismatch raises `AuthError`, never plaintext.

**Measured:**
- All **1,560** single-bit flips of the 195-byte demo blob raise `AuthError`, checked per region: version, pickup, nonce, ct and tag.
- 0 of 1000 random 195-byte blobs and 0 of 1000 random `SN2`-prefixed blobs are accepted.
- Every truncation, an extended blob, other version prefixes, splicing and wrong seeds all fail closed.
- The old 4-bit 115-byte blob, raw, zero-padded or re-wrapped to 179 bytes, fails closed. So do the old 203-byte metered blobs, raw or cut to 179 bytes.

## 7. Historical diffusion (pre-triplet; current diagnostics in `test_results.txt`)
**Method:**
- Take a 1-byte input difference at each of the 128 cells, 4 trials each, with a random state and nonce.
- Record the union of output **bytes** that differ after r keyed rounds (no whitening).
- For 4-bit N2 the same method was run on nibbles, with 6 trials.

**Historical bar-lines-only measurements below (before second coloring); historical second-coloring comparison is in §10; triplet checks are in §11 and `test_results.txt`.**

**Minimum over input positions of the dependence-union size (out of 128 cells):**

| Rounds | 1 | 2 | 3 | 4 |
|---|---|---|---|---|
| **8-bit N2 + bar lines (historical), bytes** | 57 | **128** | 128 | 128 |
| 8-bit N2 before bars, bytes | 37 | 127 | **128** | 128 |
| 4-bit N2, nibbles | 47 | 127 | **128** | 128 |
| N1, nibbles | 9 | 18 | 34 | 56 (full at round 8) |

**Mean cells changed per trial:**

| Rounds | 1 | 2 | 3 | 4 |
|---|---|---|---|---|
| **8-bit N2 + bars (random 127.5)** | 26.0 | 126.7 | 127.5 | 127.5 |
| 8-bit N2 before bars | 15.9 | 112.9 | 127.5 | 127.6 |
| 4-bit N2 (random 120) | 14.5 | 98.3 | 119.6 | 120.0 |

**Full cell dependence:** **round 2** with the bar lines, against round 3 for both 8-bit N2 before the bars and 4-bit N2.

**Historical bit avalanche, mean bits changed (min), from the earlier test run (300 samples per row, 1000 for 16 rounds):**

| Rounds | 1 | 2 | 3 | 4 | 16 |
|---|---|---|---|---|---|
| **8-bit N2 + bars, of 1024** | 88.6 (5) | 489.4 (181) | 512.1 (470) | 512.3 (458) | 512.6 (466) |
| 8-bit N2 before bars, of 1024 | 58.2 (2) | 422.2 (307) | 510.9 (465) | 511.4 (467) | 511.9 (466) |
| 4-bit N2, of 512 | 26.0 (1) | 185.6 (20) | 253.1 (54) | 256.3 (222) | 256.5 (221) |

**Same-input comparison, the fairer test** (1,500 identical samples, mean / minimum / 1st percentile / median):

| Rounds | before bars | bars after bridges (historical) | bars before bridges (rejected) |
|---|---|---|---|
| 1 | 55.7 / 2 / 16 / 57 | **88.7 / 3 / 24 / 91** | 53.6 / 4 / 15 / 55 |
| 2 | 422.6 / 121 / 322 / 426 | **489.3 / 208 / 437 / 490** | 415.3 / 137 / 313 / 418 |
| 3 | 511.2 / 459 / 474 / 512 | 511.6 / 448 / 476 / 512 | — |

- **Early-round avalanche got better** with the chosen order: the round-1 mean rose about 59%, the round-2 mean rose from 423 to 489, and the round-2 1st percentile from 322 to 437.
- The 300-sample minima in the first table are noisy. "Before bars" happened to draw 307 at round 2 there, but its true tail is lower (121 in the larger same-input run).
- From round 3 on, both versions are random-like (512 ± 16), so the bars do not change the late-round statistics.
- The ciphertext byte χ² over 2000 nonces is 237.6 (255 degrees of freedom).

## 8. Which change closes which N1 hole
| N1 hole (from `sneak_t1n/attacks/REPORT.md`) | N2 repair |
|---|---|
| No integrity: ~1/255 random blobs "decoded" | HMAC-SHA256 over `SN2‖nonce‖ct`, checked first and constant-time: 0/2000 random blobs, 0/1432 flips |
| Linear, invertible schedule | SHA-256 staff sponge over seed‖nonce; separate MAC domain |
| Interval mix, best additive characteristic ≈ 0.44 | Byte staff butterflies + 1:1 cross-shell bridges + five bar-line mixes every round; full dependence at round 2 |
| Shuffled 4-bit S-box, DDT 8/16 | Keyed SM4-affine **8-bit** S-box per round: DDT 4/256, LAT 16/256, on all 128 bytes |
| Fixed S-box / nonce-reuse guesser | All round material is a function of seed **and** nonce |

## 9. Remaining limitations (honest)
- **The SPN is unreviewed.** `attacks/` is still the 4-bit report; the later attack folders describe their respective earlier revisions, not the new triplet cipher. No full new attack campaign was run here. The numbers above are crude statistics, not bounds. Nobody has counted active S-boxes or trails, or done integral or related-nonce analysis.
- **The primitive two-cell mix has branch number 2 and partly linear bit-planes** (§4). The LSB plane is GF(2)-linear and msb differences pass deterministically. Only the S-boxes break this, which explained the historical bar-lines-only 1-round minimum of 2 bits.
- **The bar lines are linear.** They speed up cell-level diffusion but add no nonlinearity. Stacked linear layers can partly cancel; the other placement measurably did. The bar+triplet composite has been checked for one-active-input crossings (§11); multi-active-input/full-round bounds are not established.
- **The S-box class is the inversion class** (same as AES, SM4, Camellia, ARIA). It is well studied, which is good, and it also carries known algebraic structure (low-degree implicit equations of the inverse map). Affine keying does not change that class.
- **Single block only:** at most 127 bytes. There is no mode for longer messages.
- **Deterministic AE:** the SIV-style nonce means the same message always gives the same blob. Caller-chosen nonce reuse is gone, and `encrypt(guess, nonce=target_nonce)` is rejected unless that nonce is the SIV value for `guess`. But anyone with an encryption oracle can still test `encrypt(guess) == target` as a dictionary/PIN check, and equal messages are visibly equal. The PIN oracle is **not** fully dead.
- **Side channels:** this is Python with 256-entry table lookups (cache-timing exposure). It is not constant-time apart from the tag comparison.
- **Integrity** rests on HMAC-SHA256 and the secrecy of the seed. **Confidentiality** rests on the homemade SPN, which is the unproven part.
- **Not a replacement for AES-GCM-SIV, age or libsodium.**

## 10. Contrast
- **v13:** AES-256-GCM with a homemade wrapper.
- **N1:** fully homemade, with no MAC and a linear schedule. It was broken by the attack suite.
- **4-bit N2:** a repaired 512-bit SPN with 4-bit PRESENT-affine boxes.
- **8-bit N2 (current):**
  - a homemade 1024-bit SPN with keyed SM4-affine 8-bit S-boxes, a matching mod-256 byte mix, and seven pair mixes plus six triplets per pass per open 8-beat staff (four bars of 2/4), on dual octahedra;
  - sealed with HMAC-SHA256 and keyed through a SHA-256 sponge;
  - a better margin per active S-box than 4-bit N2, but still a puzzle or art piece, not protection.

## Historical second-coloring revision and compatibility

Historical order before triplets/joins: XOR round key → first coloring → weave → staff butterfly → shell bridges → B0–B4 → second coloring → B0–B4 encore. Current order is in §5 and §11. Layout stays 16×8 bytes, 16 rounds, final whitening unchanged in form, 179-byte `SN2 || nonce || ct || tag` layout, encoding and MAC domain unchanged.

At the historical second-coloring step, the old 179-byte demo still authenticated under the then-unchanged MAC, but decrypted to malformed encoding and raised **DecodeError**. Pre-clef demos now fail the clef-bound tag; same-clef pre-triplet demos still authenticate (§11). This is not authenticated version separation: a legacy blob could accidentally decode as a different valid message. Only the tested legacy demo is confirmed to fail closed; no universal old-format rejection is claimed. A future production format would need a distinct authenticated version/domain, outside this requested change.

`compare_color2.py` records matched empirical results in `color2_comparison.json`; it requires the pre-coloring backup at `/tmp/sneak_n2_8bit_precolor2`. These are sampling diagnostics, not proof of dependence for every input or security bounds. `attacks/` remains the old 4-bit report and was not re-run. Still homemade and NOT for real secrets: use AES-GCM-SIV, age, or libsodium.

### Matched empirical comparison (second coloring)

300 identical seeded nonce/input/bit-flip samples per round; dependence uses all 128 positions × four trials.

| Diagnostic | Bars only | With S2 |
|---|---:|---:|
| Full sampled byte-dependence union | round 2 | round 2 |
| Minimum byte unions rounds 1–3 | 57,128,128 | 57,128,128 |
| 1-round mean flipped bits /1024 | 88.20 | 103.74 |
| 1-round minimum / 1st percentile | 2 / 14 | 9 / 51 |
| 2-round mean flipped bits /1024 | 487.42 | 508.79 |
| 2-round minimum / 1st percentile | 152 / 435 | 194 / 459 |

The schedule changes after round 0, so later-round differences include both schedule and layer changes. These results do not establish cryptographic security.

## Clef, encore and SIV nonce (unchanged by triplets)

- **Current round order:** ⊕ rk → S → weave → butterfly → bridges → seven pairs → six triplets → S2 → encore seven pairs → encore six triplets. Decrypt reverses this, starting with encore triplets. The encore prevents per-cell fusion of S2 with the next round's S.
- **Clef:** `clef = StaffSponge(b"C", seed, bytes(16)).take(16)`, seed-only (avoids a cycle with the nonce), not in the blob.
- **Tag:** `HMAC-SHA256(mac_key, clef ‖ "SN2" ‖ nonce ‖ ct)`, `mac_key = StaffSponge(b"M", seed, nonce)`, checked with `compare_digest` before any decryption. Pre-clef 179-byte blobs (including every earlier 8-bit demo) now raise `AuthError`, not `DecodeError` or the wrong plaintext.
- **SIV nonce:** `nonce = SHA-256(clef ‖ encode_block(msg))[:16]`; `Schedule(seed, nonce)`. After the tag and decode pass, decrypt recomputes the SIV nonce from the recovered message; mismatch → `AuthError`.
- **Demo:** "hello world" → nonce `b98b9c3815374fac6048ec47c9760eb3` (see `hello-world.txt`).
- **Honest limits:** this is deterministic AE, so `encrypt(guess) == target` still works as a dictionary/PIN check for anyone who can encrypt, and identical messages produce identical blobs. Per-cell fusion is blocked, but same-clef pre-triplet/pre-join/testn3 tags still verify (old-blob version separation is NOT fixed); `attacks/` and `attacks_8bit/` were **not** re-run against this version. Still homemade and **not for real secrets** — use AES-GCM-SIV, age, or libsodium.

## 11. Triplet fix (current, 2026-11-08)

Historical pre-field-retune revision: only the triplet fix had been applied. This remains **N2 / SN2**, not N3. The dual-octahedra / hex-grid design, 16 faces × 8 bytes, two keyed SM4-affine colorings and all seven named 2×2 pair matrices remain unchanged. There is no AES wrapper, field-mix substitution, random pickup/anacrusis or key-signature/version commitment.

### Matrices and placement

Each staff, on **both inner and outer shells**, gets the six overlapping adjacent windows below in ascending order. Each matrix acts on a column vector over **Z/256Z**, with all results reduced modulo 256. The layer copies the input grid. The inverses are adjugate/determinant inverses and are applied in **reverse window order T5..T0**.

| Name | Beats (0-based) | Matrix (rows) | Integer determinant |
|---|---|---|---:|
| T0 | (0, 1, 2) | `((5, 1, 1), (2, 3, 1), (5, 5, 2))` | 1 |
| T1 | (1, 2, 3) | `((1, 3, 1), (3, 5, 2), (3, 2, 1))` | 1 |
| T2 | (2, 3, 4) | `((2, 1, 1), (1, 3, 1), (3, 3, 2))` | 1 |
| T3 | (3, 4, 5) | `((3, 3, 1), (2, 5, 3), (1, 3, 2))` | 1 |
| T4 | (4, 5, 6) | `((1, 1, 1), (1, 3, 2), (3, 2, 3))` | 1 |
| T5 | (5, 6, 7) | `((2, 1, 3), (3, 1, 3), (1, 2, 5))` | 1 |

Every row and column has at least two odd entries. The matrices were found by searching small positive coefficients `{1,2,3,5}` for integer determinant 1 and checking the composed layer's parity columns, not by assuming all small matrices are invertible. They are pairwise distinct. Exact two-sided inverse products and random-grid round trips are checked in the suite.

There are **7 pair mixes + 6 triplet mixes = 13 local maps per staff per pass**, and two passes per round (26 per staff; 416 maps over all 16 staffs). This count excludes the unchanged butterfly and bridges. Windows are exactly `(0,1,2), (1,2,3), (2,3,4), (3,4,5), (4,5,6), (5,6,7)`. **No wrap** `(6,7,0)` or `(7,0,1)`, and no direct join of beat 8 to beat 1. Overlapping passes can transmit dependence along the open line; no-wrap does not prohibit such indirect dependence.

Round order:
```
XOR rk -> S -> weave -> butterfly -> bridges
       -> bars (B0,B1,M2,B2,M3,B3,B4) -> triplets (T0..T5)
       -> S2 -> encore bars (same seven) -> encore triplets (same six)
```
Decryption starts with **encore triplet_unmix**, then encore bar_unmix, SI2, mid-round triplet_unmix, mid-round bar_unmix, inverse bridges, inverse butterfly, unweave, SI and XOR rk. Final whitening is unchanged. Tests compare the explicit forward/inverse pipelines and instrument the actual call sequence.

### Why triplets, and what was proved

An all-odd 2×2 has even determinant and cannot be invertible mod 256. **An all-odd 3×3 cannot be invertible either:** every 2×2 minor is even (equivalently, its reduction mod 2 is the rank-one all-ones matrix), so the determinant is even. Triplets do **not** evade that fact. Instead these invertible matrices allow even entries but give every column at least **two odd coefficients**, leaving two surviving output cells when an even term cancels a high-bit difference.

For a single changed input cell j, write its values as `x` and `x XOR a`, with `a != 0`. The additive difference is `d = ((x XOR a) - x) mod 256`, which is nonzero. Output additive differences are exactly `M[:,j] * d mod 256`, **independent of the values/completions of the other cells**. An odd coefficient is a unit mod 256 and cannot annihilate nonzero d. Output XOR support equals additive support (both are zero exactly when the two values are equal).

The suite exhausts **all 3 × 255 × 256** choices of j, a and x for each matrix; this is an exact reduction of all choices of the other two cells, not a sample. Every case represents **all 256² completions**. There are **zero single-cell output events**, for all nonzero single-cell XOR input differences, not just probability-1 or 0x80 events. Each individual triplet changes at least two outputs. No rare exceptions were found because the unit-coefficient argument rules them out entirely.

Composition can cancel spreading, so individual matrices are not sufficient evidence. We computed the exact 8×8 composed matrices over Z/256 by applying each layer to all eight basis vectors. The number of **odd coefficients in each column**, also the exact output weight for a one-cell `0x80` XOR difference, is:

| Input beat (0-based) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Triplet-only layer | 5 | 5 | 3 | 5 | 5 | 4 | 3 | 3 |
| **Bars then triplets (also encore)** | **5** | **5** | **5** | **3** | **5** | **3** | **3** | **2** |

Thus **all probability-1 single-cell 0x80 crossings through the combined bar+triplet layer and the encore are gone**. Stronger: at least two odd coefficients per composite column prove no single-cell output event for **any** nonzero single-cell input difference at **any** base state. This statement is about those layers, not a lower bound on full-round trails involving the butterfly, bridges, nonlinear colorings and multiple active inputs.

### Current verification

The full suite completed with **114/114 checks passed, 0 failed**; output is in `test_results.txt`. This includes all original checks, triplet regressions, 256 pre-triplet and 256 pre-join random old blobs (all fail closed), and pre-clef authentication rejection. The first run stopped on a test-harness `inspect` error for an unregistered dynamically loaded backup module; registering that module fixed the harness, with no cipher change, and the complete rerun passed.

Current sampled byte-dependence min-unions for rounds 1–6 are `[80,128,128,128,128,128]`, reaching the full union at round 2. Mean affected bytes after one round is 50.7. Bit-avalanche means /1024 for rounds 1,2,3,4,16 are `201.8,511.6,509.8,512.4,512.0`; the 16-round minimum is 462 (1000 samples). Ciphertext-byte chi-square is 248.1 (255 df, 2000 random messages). These are sampling diagnostics, not security bounds or matched comparisons against the older tables.

### Honest leftovers and compatibility

- The seven pair matrices still have even coefficients and still leak single-cell high-bit differences **when considered alone**. The new triplet layers stop those singleton crossings through the **combined bar+triplet** pass. This is not a conversion to GF(2^8).
- All these mixes are still linear over Z/256Z; carries go upward, the LSB plane is GF(2)-linear, and `0x80` differences still propagate **deterministically**, now to multiple cells. Multi-input cancellation and other differential/algebraic weaknesses remain possible. No full-cipher security or MDS/branch-number claim is made.
- **PIN dictionary guessing is unchanged:** deterministic SIV means `encrypt(guess) == target_blob` still works for anyone with encryption access, and equal messages produce equal blobs. No randomness was added.
- **Pre-triplet, pre-join and testn3 blobs still pass the live tag**, because the clef, MAC formula/key and `SN2` prefix are unchanged. The tested old blobs fail closed with DecodeError or AuthError, never plaintext; this is not a universal authentication-rejection guarantee. A wrong plaintext would still have to pass the subsequent 128-bit SIV check. Pre-clef blobs fail authentication. No key-signature, domain bump or version change was applied.
- The blob is still **179 bytes**: `SN2 || nonce(16) || ct(128) || tag(32)`. Clef domain, SIV nonce, MAC formula, encoding, seed path, S-boxes, weave, butterfly, bridges and deterministic/no-urandom encrypt are unchanged.
- `hello-world.txt` is regenerated **as text only**; decrypt returns `b'hello world'`. The nonce remains `b98b9c3815374fac6048ec47c9760eb3`; ciphertext and tag changed.
- **No PNG was regenerated.** `sneak-staff-n2.png` shows the pre-triplet grid (and also predates the pair joins), not the current text demo. The old attack folders and named snapshots are unchanged; no new attack campaign was run. Earlier empirical tables are historical, not current triplet results. Current checks and diagnostics are in `test_results.txt`.
- Backup before edits: `/tmp/sneak_n2_pre_triplet` (tree copy excluding `__pycache__`).

Still **homemade, unreviewed, not for real secrets**. Use **AES-GCM-SIV, age, or libsodium** for those.

## Fixed test vectors (for independent implementations)

Use these to check another implementation. Each vector fixes the 16-byte pickup
(`000102...0f`, normally `os.urandom`), so `encrypt` is deterministic. The seed is
`sneak1024-seed.txt` as loaded by `load_seed()`. Every blob must decrypt to its
message. A correct decryptor also rejects the three negative cases below.

Seed and key signature (for the seed-loading check):

| item | value |
|---|---|
| seed SHA-256 | `8d1f7c16876c149c2d445c2817a230ffaaec9d8a2fc9769e2f3aae155e3b8e24` |
| key signature (16 bytes) | `a09a745ee41908c969c21a7d45577870` |
| pickup used | `000102030405060708090a0b0c0d0e0f` |
| blob length | 196 bytes (`MAX_MSG` = 127, `BLOB_LEN` = 196) |

Positive vectors (message to blob):

| name | msg length | nonce (SIV, 16 bytes) | blob (196 bytes, hex) |
|---|---|---|---|
| empty | 0 | `56e3184d97a5a8fb1e704cf1d6fb0819` | `01534e32000102030405060708090a0b0c0d0e0f56e3184d97a5a8fb1e704cf1d6fb0819c56b7b8ce93aa3f5c65eeaaef3b7df22a48197534fa56fa480faa71d8a32bb5b3bf25eaaeef99ce81acc8a096b6570de1eee02065d527ef1e8990101f060c7185fde23ab1ef27e19b4360aa31f69c066ad1c7b67e0f4e1e333462e0fdf3a37d9f3cdb348a2ab648cc26e7c8928f6902d322216990a5f9b9398fba4f77b7784e5ba75974e29338e9c3213956ec087e3e22c7e51616d1928c6b95013c042e730fa1ef27e19b4360aa31f69c066ad1c7b67e0f4e1e333462e0fdf3a37d9f3cdb348a2ab648cc26e7c8928f6902d322216990a5f9b9398fba4f77b7784e56155ce80f1888733b1f9ad4d9f8270ea855eeb441f3a30b3e5de49da444463d7` |
| hello world | 11 | `8ead058c248507c42c799033fb03a546` | `01534e32000102030405060708090a0b0c0d0e0f8ead058c248507c42c799033fb03a54605b152b4f8e399bd46847dfc1f05074bd05c4ec7247357a9823cfb5435ace6e2aa5a87aed414f069e3a71fdb371c51af37d6762fa63cb5fae4fa67d6cc89cd20795e4c12048e842e942e8cb6686331962fb2c504758974994f773a142d2f58809e8704238551f1d83a0540df27d8382cfa8ef0d76830337bc4468c11a7d2e9fd8d04bb912a573eda5121207d9922056696cc3456e511d4f44ee637938a03c4df95e4c12048e842e942e8cb6686331962fb2c504758974994f773a142d2f58809e8704238551f1d83a0540df27d8382cfa8ef0d76830337bc4468c11a7d2e9fdcce477814a6c2bc9eae65a86d2b670df9e839a01bff5e01f2ca019536b8b72a6` |
| max (127 x M) | 127 | `2b3ac480f04caf1eaa19a7f4b97dafe9` | `01534e32000102030405060708090a0b0c0d0e0f2b3ac480f04caf1eaa19a7f4b97dafe972835c6b376607f0c5dc14944cd17694e42ed89d1a23eb7cda07b7877a5e5a2a9a7f0eedb0c09b3403738c39f639b991580ad55770c2b82ab21c8db38d39cc4c7a8bd3c6dca56996835f94ad83d9dbe1a4eb17eceb96a2e76154c08ee042b6916c3ca65a0c7595346a1f7a96ff7e3fb05da10eca0181d480f1d38552487555144019d59ee66fd04dd6c6c0a3cb66ff31e79a209b6d6a2b8258efae282d99ad4f4c7a8bd3c6dca56996835f94ad83d9dbe1a4eb17eceb96a2e76154c08ee042b6916c3ca65a0c7595346a1f7a96ff7e3fb05da10eca0181d480f1d3855248755514767197f708be0c4ba91f371f19c38019171b4a5c00ae83f4aba8d6b5b7f1184b` |

Negative cases (each must raise an authentication error, not return plaintext):

| name | input |
|---|---|
| tampered tag | the `hello world` blob with its last byte XOR 0x01 |
| bad version byte | the `hello world` blob with byte 0 set to `00` |
| truncated | the `hello world` blob with its last byte removed |

