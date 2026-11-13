# Octavo review: no cipher break, but four defects block reproducibility and deployment

> **TL;DR** — I rebuilt the round function independently, validated it against the live cipher, and attacked the
> current revision. **No distinguisher, no forgery, no key recovery.** Three defects stop the repo from running on
> a fresh clone (two hardcoded paths, two stale SHA pins, one `.pyc` incompatibility), the format has no version
> byte, and ~40 % of every `encrypt` is spent re-hashing its own source.

## Target and method

| | |
|---|---|
| Commit | `main` @ `13e8186` |
| `sneak_n2.py` (committed blob, LF) | `25cfe812ac6a5d5c22a26ba17440843f417dd44e060498850a78b68964612ff0` — matches `SNAPSHOT.md` and `README.md` |
| `key_signature` | `1946c5ac57f19d045eeacd9e5ed823fb` — matches `SNAPSHOT.md` |
| Harness | `review_fullbore.py`, NumPy model + attack pass, ~210 s on 8 cores |
| Python | CPython 3.13, Windows x86-64 (review harness host only). The committed rehearsal constant `f28badba…` matches the Linux errno set `{1, 18, 31, 38, 95}`, not this host's set. |

The working tree I tested is CRLF (`core.autocrlf`), so the raw file hashes to `d296d13e…` locally. The committed
LF blob hashes to `25cfe812…`, and `key_signature` is unchanged under CRLF, so tags are stable across line
endings. No source file was modified.

I rebuilt the bow / rehair / bar / triplet / cross layers and the full 16-round cipher in NumPy, and validated
the model against the live `round_enc` for all 16 rounds and against whitened `encrypt_grid` before trusting any
result from it.

## Severity scale

* **High** — blocks a stated use of the repo, or makes a headline claim unverifiable.
* **Medium** — leaks correctness or cost in normal use; workaround exists.
* **Low** — maintenance hazard or sharp edge; no incorrect behaviour today.

## Findings

| # | Severity | Finding |
|---|---|---|
| 1 | High | Hardcoded `/workspace` seed path breaks the README quick start and the entire test suite |
| 2 | High | Published attack log cannot be replayed: hardcoded paths **and** SHA pins two revisions stale |
| 3 | High | `inspect.getsource`-based `key_signature` makes `encrypt`/`decrypt` raise outside a source tree |
| 4 | Medium | No format version: any revision change silently invalidates all ciphertext as "tag mismatch" |
| 5 | Medium | `key_signature` is ~40 % of every `encrypt` and `decrypt` |
| 6 | Low | Attestation is fragile both ways: dead constants are attested, new constant types are fatal |
| 7 | Low | `seed=1` accepted silently — 1 nonzero byte of 128 |
| 8 | Low | 68-byte overhead, 127-byte message cap, ~1.6 KiB/s payload throughput |

---

### 1. [High] Hardcoded `/workspace` seed path breaks the quick start and the whole test suite

`SEED_PATH = "/workspace/sneak1024-seed.txt"` is an absolute path from the author's machine, and `load_seed()`
uses it as a default argument. Every zero-argument call therefore fails on a clone — including the README's own
example and line 5 of `test_sneak_n2.py`, before a single test runs. The consequence is that the advertised
"237/237 passed" cannot be checked by anyone but the author.

**Evidence**

```
$ python3 -c "import sneak_n2 as n; n.encrypt(b'hello world')"
FileNotFoundError: [Errno 2] No such file or directory: '/workspace/sneak1024-seed.txt'

$ python3 test_sneak_n2.py
  File "test_sneak_n2.py", line 5, in <module>
    SEED = N.load_seed(); R = random.Random(2); P = F = 0
  File "sneak_n2.py", line 44, in load_seed
    h = "".join(c for c in open(path).read().lower() if c in "0123456789abcdef")
FileNotFoundError: [Errno 2] No such file or directory: '/workspace/sneak1024-seed.txt'
```

**Reproduce**

```bash
python3 -c "import sneak_n2 as n; n.encrypt(b'hello world')"
python3 test_sneak_n2.py
```

**Fix** — make the default relative to the module, and both the README example and the suite work:

```python
SEED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sneak1024-seed.txt")
```

---

### 2. [High] The published attack log cannot be replayed

`REPORT.md` states the replay "runs 16 checks in about 3.7 s and prints REPLAY PASS". From a clone it dies on the
first line, for two independent reasons:

1. every script asserts a `/workspace/sneak_n2/sneak_n2.py` path that does not exist;
2. the pinned SHA (`922a29d8…` in `attacks_octavo_beat6/common.py`) is **two revisions older** than the file the
   repo ships (`25cfe812…`).

`fix_beat0rot_verification/common.py` has the same two problems. Since a reproducible public attack log is the
repo's main claim, this is the most consequential finding.

**Evidence**

```
$ python3 attacks_octavo_beat6/attack_replay.py
FileNotFoundError: [Errno 2] No such file or directory: '/workspace/sneak_n2/sneak_n2.py'

$ grep -n "workspace\|EXPECTED_SHA" attacks_octavo_beat6/common.py fix_beat0rot_verification/common.py
attacks_octavo_beat6/common.py:5:EXPECTED_SHA='922a29d89be68b29a2be08873ff5a99a7cf264afebe1ece0387aa0f4fe56fe10'
attacks_octavo_beat6/common.py:6:assert hashlib.sha256(Path('/workspace/sneak_n2/sneak_n2.py').read_bytes())...
fix_beat0rot_verification/common.py:9:LIVE = Path('/workspace/sneak_n2/sneak_n2.py')
```

**Reproduce**

```bash
python3 attacks_octavo_beat6/attack_replay.py
```

**Fix** — resolve the target relative to `__file__`, and refresh `EXPECTED_SHA` to the shipped blob (or read it
from `SNAPSHOT.md` rather than duplicating it).

---

### 3. [High] `key_signature` makes the cipher unusable in any non-source deployment

`key_signature()` → `mix_description()` → `inspect.getsource()` over 62 names. That requires the `.py` files on
disk. In a zipapp, a `.pyc`-only install or a frozen executable, both `encrypt` and `decrypt` raise, because the
attestation runs on every call and there is no opt-out. The cipher can only be shipped as raw source.

**Evidence** — compiles the module to a `.pyc`-only directory, then calls the public API with an explicit key:

```
OSError: could not get source code
```

**Reproduce**

```bash
python3 - <<'PY'
import os, py_compile, subprocess, sys, tempfile
d = tempfile.mkdtemp()
py_compile.compile("sneak_n2.py", cfile=os.path.join(d, "sneak_n2.pyc"), doraise=True)
p = subprocess.run([sys.executable, "-c",
    f"import sys; sys.path.insert(0, {d!r}); import sneak_n2 as m; m.encrypt(b'x', bytes(128))"],
    capture_output=True, text=True)
print(p.stderr.strip().splitlines()[-1])
PY
```

**Fix** — replace source hashing with a behavioural known-answer digest (fixed seed → fixed ciphertext). That
commits to the implementation without needing its text, still closes the identity-`staff_mix` case the
attestation was added for, and works from bytecode. Failing that, catch the `OSError` in `key_signature` and raise
a documented error rather than failing from inside `inspect`.

---

### 4. [Medium] No format version: any revision change silently invalidates all ciphertext

`VERSION` has stayed `b"SN2"` across ten incompatible revisions, while `key_signature` — a hash of the covered
functions' *source text* — is mixed into the MAC. So a revision change (or, per finding 6, a comment edit inside a
covered function) breaks every existing blob, and the failure surfaces as `tag mismatch`: indistinguishable from
corruption or a wrong key. There is no way to tell "old format" from "tampered".

**Evidence** — change one bow constant in-process, then decrypt the blob the repo ships:

```
version field b'SN2' -> tag mismatch
```

**Reproduce**

```bash
python3 - <<'PY'
import sneak_n2 as n
seed = n.load_seed("sneak1024-seed.txt")
blob = bytes.fromhex([l for l in open("hello-world.txt") if l.startswith("blob")][0].split()[-1])
n.BOW_PRESSURE_ROT = (0,) * 7          # simulate any other revision
try:
    n.decrypt(blob, seed)
except n.AuthError as e:
    print("version field", blob[:3], "->", e)
PY
```

**Fix** — bump `VERSION` on format change and raise a distinct `UnsupportedVersion` before the tag check. Blobs
are fixed length, so a version byte is free.

---

### 5. [Medium] `key_signature` is ~40 % of every `encrypt` and `decrypt`

The attestation is recomputed from scratch on **every call** — no caching. It re-parses and re-hashes all 62
sources, plus the module data the closure reaches, of which `_GF_MUL` alone expands to **191,015 bytes** of
canonical text via `_canon_data`'s `repr()`.

**Evidence** (median of 10, CPython 3.13)

```
mix_description    ~15 ms     4,008-byte canonical JSON
key_signature      ~15 ms     -> ~40 % of encrypt
encrypt            ~37 ms
decrypt            ~40 ms
```

**Reproduce**

```bash
python3 - <<'PY'
import statistics, time, sneak_n2 as n
seed = bytes(128); blob = n.encrypt(b"x", seed)
def bench(f, k=10):
    ts = []
    for _ in range(k):
        t = time.perf_counter(); f(); ts.append(time.perf_counter() - t)
    return statistics.median(ts) * 1000
print(f"mix_description {bench(n.mix_description):6.1f} ms")
print(f"key_signature   {bench(lambda: n.key_signature(seed)):6.1f} ms")
print(f"encrypt         {bench(lambda: n.encrypt(b'x', seed)):6.1f} ms")
print(f"decrypt         {bench(lambda: n.decrypt(blob, seed)):6.1f} ms")
print(f"canon(_GF_MUL)  {len(n._canon_data(n._GF_MUL))} bytes")
PY
```

**Fix** — memoise per `(seed, source digest)`. The digest cannot legitimately change inside a process, and the
case where it does change is precisely the case the attestation cannot catch (the report's own three blind spots:
foreign globals, in-memory `__code__`, patched `builtins.divmod`).

---

### 6. [Low] Attestation is fragile in both directions

**Dead constants are attested.** `BARS[0]` keeps a `((1,5),(1,6))` matrix that `bar_mix` never applies — B0 is
special-cased to the Latin pair — yet the matrix, its inverse and its determinant are all hashed into
`key_signature`. Editing it moves every tag without changing a single ciphertext byte.

**New constant types are fatal.** `_canon_data` accepts only `None`/`bool`/`int`/`str`/`bytes`/`tuple`/`list`/`dict`
and raises otherwise, so adding (say) a module-level `set` or NumPy array that the closure reaches makes
`encrypt` raise for every message — with no version bump to signal it.

**Evidence**

```
BARS[0] matrix is never applied; key_sig changed: True | cipher unchanged: True
TypeError: cannot attest object of type set
```

**Reproduce**

```bash
python3 - <<'PY'
import sneak_n2 as n
seed = bytes(128); before = n.key_signature(seed)
n.BARS = ((n.BARS[0][0], n.BARS[0][1], n.BARS[0][2], ((7, 7), (7, 7))),) + n.BARS[1:]
print("dead BARS[0] matrix attested; key_sig changed:", before != n.key_signature(seed),
      "| cipher unchanged:", n.decrypt(n.encrypt(b"x", seed), seed) == b"x")
PY
python3 -c "import sneak_n2 as n; n._canon_data({1,2,3})"
```

**Fix** — drop the unused B0 matrix (history belongs in the docs), and assert at import time that everything the
closure reaches is encodable.

---

### 7. [Low] `seed=1` is accepted silently

`_seed_bytes(int)` does `seed.to_bytes(128, "big")`, so the integer key `1` becomes 127 zero bytes plus `0x01`.
With the hardcoded default path in finding 1, this is the easiest way to end up on a near-degenerate key with no
warning. The sponge and SIV nonce keep it from being catastrophic, but it should not be silent.

**Evidence**

```
b'x' | key bytes: 128 | nonzero key bytes: 1
```

**Reproduce**

```bash
python3 -c "import sneak_n2 as n; b=n.encrypt(b'x',1); print(n.decrypt(b,1), '| nonzero key bytes:', sum(1 for c in n._seed_bytes(1) if c))"
```

**Fix** — require 128 bytes explicitly, or warn when an integer supplies fewer than 16 significant bytes.

---

### 8. [Low] Throughput and framing

127-byte message cap, 68 bytes of overhead per blob, no mode for longer input, no associated data. Measured
payload throughput is ~1.6 KiB/s.

**Evidence**

```
encrypt ~39 ms, decrypt ~39 ms, payload ~1.6 KiB/s, overhead 68 bytes/message
```

**Reproduce**

```bash
python3 - <<'PY'
import os, time, sneak_n2 as n
seed = os.urandom(128); msg = b"A" * 127
t = time.perf_counter(); b = n.encrypt(msg, seed); e = time.perf_counter() - t
t = time.perf_counter(); n.decrypt(b, seed); d = time.perf_counter() - t
print(f"encrypt {e*1000:.0f} ms, decrypt {d*1000:.0f} ms, payload {127/(e+d)/1024:.2f} KiB/s, "
      f"overhead 68 bytes/message")
PY
```

---

## What held up under attack

All from the current revision, with the NumPy model validated against the live `round_enc` first.

* **One-beat single-byte leaks, all 8 beats: 534,773,760 cases** (262,144 staffs × 255 XOR deltas × 8 beats) →
  **0 singletons**. `one_pair_both = 0` on every beat: no change ever confined the bow delta to a single rehair
  pair with both cells changed. Minimum changed bytes after bow+rehair: **3** on beats 0/2/4/6, **2** on
  1/3/5/7. The newest `BOW_PRESSURE_ROT = (0,0,0,3,0,0,5)` fix holds under this independent scan.
* **Forced-change bow outputs** reproduce `fix_beat0rot_verification/SUMMARY.md` exactly:
  `{0:[0,1,2], 1:[0], 2:[], 3:[], 4:[5,6], 5:[], 6:[5,7], 7:[5]}`.
* **Bow linear relations** reproduce: `(c0b0⊕c1b7)→c0b0` = **+0.1453**, `c6b0→c7b4` = **+0.0398**; both stay
  inside the bow.
* **LAT of all 64 keyed tables** across two schedules: max **16/256 = 2⁻³** for every table — no weak keying.
* **1 / 2 / 3-round differentials** (65,536 / 32,768 / 8,192 chosen pairs): mean flipped bits
  **512.1 / 511.8 / 512.0** of 1024 (random 512.0); maximum repeated output difference **×1**; no distinguisher.
  Consistent with the ≥8 / ≥20 active-S-box trail bounds.
* **1-round integral** from the round input (full 256-value cell set): 2/128 zero-sum output cells vs 0.5
  expected — nothing survives.
* **AE battery:** 1560/1560 single-bit flips rejected, 200/200 random 195-byte blobs rejected, 193/193
  reversed-tail splices rejected, wrong seed rejected on tag. A crafted blob with a valid tag but a non-SIV nonce
  is correctly rejected with `SIV nonce mismatch` — reachable, but only by a key holder.

## Limits

No MILP/SAT best-trail search, no Gröbner/XL, no 4+ round differentials (needs ≫2³⁰ chosen pairs), no timing or
side-channel measurement, and no evaluation of the sponge or S-box construction beyond reproducing the reported
spectra. This is a negative experimental result, not a security proof — same caveat the repo already makes.

## Suggested order of work

1. Relative `SEED_PATH` — fixes **1**, the path half of **2**, and unblocks the test suite.
2. Refresh the attack-folder SHA pins — fixes the rest of **2**.
3. Cache or replace `key_signature` — fixes **3**, **5**, **6**.
4. Add a version byte and a distinct error — fixes **4**.
5. Validate integer seeds — fixes **7**.

Items 1 and 2 are a few lines and make the repo self-verifying; 3 and 4 are a small refactor. Happy to send a PR
for 1–2 and a branch for 3–4.
