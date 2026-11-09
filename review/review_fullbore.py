"""Independent full-bore pass on the LIVE Octavo revision (beat-0 pressure-rotation fix).

Read-only with respect to the cipher. Rebuilds the bow/rehair/bar/triplet/cross layers and the
full round in NumPy, validates against live round_enc/encrypt_grid, then attacks:

  S1 model validation          16 rounds + whitening vs live cipher
  S2 single-byte-leak scan     bow+rehair, all 8 beats (the property the newest fix claims)
  S3 forced-change sets        which bow outputs always change, per input beat
  S4 bow linear relations      the two relations the author reports
  S5 round-level differentials 1, 2 and 3 rounds of chosen-input pairs
  S5b one-cell integral        256-value set through 1 round, zero-sum output cells
  S6 LAT spectrum              every keyed table in two schedules
  S7 AE battery                bit flips, splices, random blobs, wrong seed, crafted SIV blob
  S8 implementation findings   default seed path, sourceless install, key_signature cost, versioning

Run:  python3 review/review_fullbore.py   (needs numpy)
"""
import sys, os, time, hashlib, collections, shutil, py_compile, tempfile, subprocess

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = HERE if os.path.exists(os.path.join(HERE, "sneak_n2.py")) else os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import numpy as np
import sneak_n2 as N

SEED = N.load_seed(os.path.join(ROOT, "sneak1024-seed.txt"))
GF = np.array([list(x) for x in N._GF_MUL], dtype=np.int64)
GF2 = GF[2]
RESULTS = []


def record(section, ok, msg):
    RESULTS.append((section, ok, msg))
    print(("[PASS] " if ok is True else ("[FAIL] " if ok is False else "[INFO] ")) + f"{section}: {msg}",
          flush=True)


# ---------------------------------------------------------------- staff-local layers
def rotl(x, r):
    x = np.asarray(x, dtype=np.int64)
    r = np.asarray(r, dtype=np.int64)
    return ((x << r) | (x >> (8 - r))) & 255


def latin(u, v, S, S2):
    return S[u ^ v], S2[u ^ GF2[v]]


def bow_s(x):
    """(n,8) staffs -> bow_pressure, including BOW_PRESSURE_ROT."""
    x = np.asarray(x, dtype=np.int64).copy()
    for (i, j, p), k in zip(N.BOW_STROKES, N.BOW_PRESSURE_ROT):
        pp = rotl(x[:, p], k)
        r1 = N.BOW_ROT_BASE + (pp % N.BOW_ROT_MOD)
        r2 = N.BOW_ROT_BASE + ((pp >> N.BOW_R2_SHIFT) % N.BOW_ROT_MOD)
        v = x[:, j]
        u = (x[:, i] + rotl(v, r1)) & 255
        x[:, i] = u
        x[:, j] = v ^ rotl(u, r2)
    return x


def rehair_s(x, S, S2):
    x = np.asarray(x, dtype=np.int64).copy()
    for t in (1, 3, 5, 7):
        u, v = x[:, t - 1].copy(), x[:, t].copy()
        x[:, t - 1], x[:, t] = latin(u, v, S, S2)
    return x


# ---------------------------------------------------------------- staff/beat layers on (n,16,8)
def bars_g(x, S, S2):
    x = x.copy()
    for name, _, (i, j), M in N.BARS:
        u, v = x[:, :, i].copy(), x[:, :, j].copy()
        if name == "B0 start":
            x[:, :, i], x[:, :, j] = latin(u, v, S, S2)
        else:
            x[:, :, i] = GF[M[0][0], u] ^ GF[M[0][1], v]
            x[:, :, j] = GF[M[1][0], u] ^ GF[M[1][1], v]
    return x


def trips_g(x):
    x = x.copy()
    for _, (i, j, k), M in N.TRIPLETS:
        u, v, w = x[:, :, i].copy(), x[:, :, j].copy(), x[:, :, k].copy()
        for pos, (a, b, c) in zip((i, j, k), M):
            x[:, :, pos] = (a * u + b * v + c * w) & 255
    return x


def mix2v(u, v):
    return GF[1, u] ^ GF[1, v], GF[1, u] ^ GF[2, v]


def bow_g(x):
    x = x.copy()
    for (i, j, p), k in zip(N.BOW_STROKES, N.BOW_PRESSURE_ROT):
        pp = rotl(x[:, :, p], k)
        r1 = N.BOW_ROT_BASE + (pp % N.BOW_ROT_MOD)
        r2 = N.BOW_ROT_BASE + ((pp >> N.BOW_R2_SHIFT) % N.BOW_ROT_MOD)
        v = x[:, :, j]
        u = (x[:, :, i] + rotl(v, r1)) & 255
        x[:, :, i] = u
        x[:, :, j] = v ^ rotl(u, r2)
    return x


def rehair_g(x, S, S2):
    x = x.copy()
    for t in (1, 3, 5, 7):
        u, v = x[:, :, t - 1].copy(), x[:, :, t].copy()
        x[:, :, t - 1], x[:, :, t] = latin(u, v, S, S2)
    return x


def cross_g(x):
    x = x.copy()
    for matching in N.CROSS_LAYERS:
        for i, j in matching:
            u, v = x[:, i, :].copy(), x[:, j, :].copy()
            x[:, i, :], x[:, j, :] = mix2v(u, v)
    return x


class Cipher:
    def __init__(self, sch):
        self.sch, self.perm, self.staff, self.shell = sch, [], [], []
        self.S, self.S2, self.rk = [], [], []
        ident = [list(range(f * 8, f * 8 + 8)) for f in range(16)]
        for r, k in enumerate(sch.rounds):
            self.perm.append(np.array(N.weave(ident, k["SH"], k["SV"])).reshape(128))
            layers = []
            for m in N.LAYERS:
                p = [(f * 8 + s[i], f * 8 + s[i | m])
                     for f, s in enumerate(k["sigma"]) for i in range(8) if not i & m]
                layers.append((np.array([q[0] for q in p]), np.array([q[1] for q in p])))
            self.staff.append(layers)
            a = np.arange(64)
            b = (np.array(k["bridge"]) // 8 + 8) * 8 + np.array(k["bridge"]) % 8
            self.shell.append((a, b) if r % 2 == 0 else (b, a))  # even: u=inner, odd: u=outer
            self.S.append(np.array(k["S"]))
            self.S2.append(np.array(k["S2"]))
            self.rk.append(np.frombuffer(N.grid_to_bytes(k["rk"]), dtype=np.uint8).astype(np.int64))
        self.white = np.frombuffer(N.grid_to_bytes(sch.white), dtype=np.uint8).astype(np.int64)

    def linear(self, x, r):
        x = x[:, self.perm[r]].copy()
        for a, b in self.staff[r] + [self.shell[r]]:
            u, v = x[:, a].copy(), x[:, b].copy()
            x[:, a], x[:, b] = mix2v(u, v)
        return x

    def half(self, x, r):
        S, S2 = self.S[r], self.S2[r]
        x = np.asarray(x).reshape(-1, 16, 8)
        out = cross_g(rehair_g(bow_g(trips_g(bars_g(x, S, S2))), S, S2))
        return out.reshape(-1, 128)

    def round(self, x, r):
        x = self.S[r][x ^ self.rk[r]]
        x = self.half(self.linear(x, r), r)
        return self.half(self.S2[r][x], r)

    def enc(self, x, rounds=16, white=True):
        for r in range(rounds):
            x = self.round(x, r)
        return x ^ self.white if white else x

    def validate(self, n=6, seed=99):
        rng = np.random.default_rng(seed)
        x = rng.integers(0, 256, (n, 128))
        y = x.reshape(n, 16, 8).copy()
        for r in range(16):
            y = self.round(y.reshape(n, 128), r).reshape(n, 16, 8)
            for i in range(n):
                live = N.round_enc(N.bytes_to_grid(bytes(x[i].astype(np.uint8))), self.sch.rounds[r], r)
                exp = np.frombuffer(N.grid_to_bytes(live), dtype=np.uint8).astype(np.int64)
                assert np.array_equal(y[i].reshape(128), exp), (r, i, "round mismatch")
                x[i] = exp
        raw = rng.integers(0, 256, (1, 128))
        got = bytes(self.enc(raw, 16, True)[0].astype(np.uint8))
        want = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(bytes(raw[0].astype(np.uint8))), self.sch))
        assert got == want, "whitened mismatch"
        return n


def scan_worker(job):
    bases, beat, S, S2 = job
    a = bow_s(bases)
    ar = rehair_s(a, S, S2)
    hits = one_pair = 0
    minw, hist = 99, np.zeros(9, dtype=np.int64)
    for d in range(1, 256):
        h = bases.copy()
        h[:, beat] ^= d
        b = bow_s(h)
        z = a ^ b
        act = z != 0
        one = act.sum(1) == 1
        for i in (0, 2, 4, 6):
            m = one & act[:, i] & act[:, i + 1]
            if m.any():
                one_pair += int(m.sum())
                hits += int((m & ((z[:, i] == z[:, i + 1]) | (z[:, i] == GF2[z[:, i + 1]]))).sum())
        w = (ar != rehair_s(b, S, S2)).sum(1)
        minw = min(minw, int(w.min()))
        hist += np.bincount(w, minlength=9)
    return beat, hits, one_pair, minw, hist.tolist(), len(bases) * 255


def main():
    t0 = time.time()
    sha = hashlib.sha256(open(os.path.join(ROOT, "sneak_n2.py"), "rb").read()).hexdigest()
    record("target", None, f"sneak_n2.py sha256={sha}")
    record("target", None, f"BOW_STROKES={N.BOW_STROKES} BOW_PRESSURE_ROT={N.BOW_PRESSURE_ROT}")
    assert N.BOW_PRESSURE_ROT == (0, 0, 0, 3, 0, 0, 5)
    demo_nonce = bytes.fromhex(open(os.path.join(ROOT, "demo-nonce.txt")).read().strip())
    sch = N.Schedule(SEED, demo_nonce)
    C = Cipher(sch)

    # S1
    C.validate(6)
    record("S1 model", True, "NumPy round == live round_enc for all 16 rounds; whitened encrypt_grid matches")

    # S7 AE battery
    hb = bytes.fromhex(next(l for l in open(os.path.join(ROOT, "hello-world.txt"))
                            if l.startswith("blob")).split()[-1])
    assert N.decrypt(hb, SEED) == b"hello world"
    bad = 0
    for bit in range(1560):
        b2 = bytearray(hb)
        b2[bit // 8] ^= 1 << (bit % 8)
        try:
            N.decrypt(bytes(b2), SEED)
            bad += 1
        except N.AuthError:
            pass
    record("S7 AE", bad == 0, f"all 1560 single-bit flips rejected ({bad} accepted)")

    rng = np.random.default_rng(7)
    rej = 0
    for _ in range(200):
        try:
            N.decrypt(bytes(rng.integers(0, 256, N.BLOB_LEN, dtype=np.uint8)), SEED)
        except N.AuthError:
            rej += 1
    record("S7 AE", rej == 200, f"{rej}/200 random blobs rejected")

    muts = [hb[:c] + hb[c:][::-1] for c in range(1, N.BLOB_LEN - 1)]  # cut=194 reverses a 1-byte tail = identity
    sp = 0
    for m in muts:
        try:
            N.decrypt(m, SEED)
        except N.AuthError:
            sp += 1
    record("S7 AE", sp == len(muts), f"{sp}/{len(muts)} reversed-tail splices rejected (cuts 1..193; "
                                     f"cut=194 is the identity and is excluded)")

    try:
        N.decrypt(hb, bytes(128))
        record("S7 AE", False, "wrong seed accepted the demo blob")
    except N.AuthError:
        record("S7 AE", True, "wrong seed rejected on tag")

    clef = N.staff_clef(SEED)
    pickup = os.urandom(16)
    block = N.encode_block(b"crafted")
    nonce = os.urandom(16)
    s2 = N.Schedule(SEED, nonce)
    ct = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(block), s2))
    crafted = N.VERSION + pickup + nonce + ct + N._tag(s2.mac_key, pickup, nonce, ct, clef,
                                                       N.key_signature(SEED))
    try:
        N.decrypt(crafted, SEED)
        record("S7 AE", False, "crafted non-SIV blob accepted")
    except N.AuthError as e:
        record("S7 AE", True, f"crafted valid-tag/non-SIV blob rejected: '{e}' (post-decode SIV branch works, key-holder only)")

    # S8
    try:
        N.encrypt(b"x")
        record("S8 impl", False, "default seed path worked")
    except FileNotFoundError:
        record("S8 impl", True, f"encrypt() with default seed -> FileNotFoundError (SEED_PATH={N.SEED_PATH})")

    t = time.perf_counter(); N.mix_description(); md = time.perf_counter() - t
    t = time.perf_counter(); N.key_signature(SEED); ks = time.perf_counter() - t
    t = time.perf_counter()
    for _ in range(3):
        N.encrypt(b"timing", SEED)
    en = (time.perf_counter() - t) / 3
    record("S8 impl", None, f"mix_description={md*1000:.1f} ms, key_signature={ks*1000:.1f} ms, "
                            f"encrypt={en*1000:.1f} ms -> {100*ks/en:.0f}% of encrypt is source re-attestation")

    tmp = tempfile.mkdtemp(prefix="oct_", dir=ROOT)
    try:
        py_compile.compile(os.path.join(ROOT, "sneak_n2.py"),
                           cfile=os.path.join(tmp, "sneak_n2.pyc"), doraise=True)
        p = subprocess.run([sys.executable, "-c",
                            f"import sys; sys.path.insert(0,{tmp!r}); import sneak_n2 as m;"
                            f"m.key_signature(bytes(128))"], capture_output=True, text=True)
        ok = p.returncode != 0 and ("OSError" in p.stderr or "could not get source" in p.stderr)
        record("S8 impl", ok, "sourceless (.pyc-only) install breaks key_signature -> encrypt/decrypt unusable")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    keep = N.BOW_PRESSURE_ROT
    try:
        N.BOW_PRESSURE_ROT = (0,) * 7
        try:
            N.decrypt(hb, SEED)
            record("S8 impl", False, "other-revision blob accepted")
        except N.AuthError as e:
            record("S8 impl", True, f"a different revision's blob is still labelled SN2 and fails as '{e}' "
                                    f"(no format version field)")
    finally:
        N.BOW_PRESSURE_ROT = keep

    # S2 singleton scan
    cpu = os.cpu_count() or 4
    nb = 1 << 18
    bases = np.random.default_rng(66061).integers(0, 256, (nb, 8))
    S0, S20 = C.S[0], C.S2[0]
    from multiprocessing import Pool
    with Pool(min(cpu, 8)) as P:
        out = P.map(scan_worker, [(bases, t, S0, S20) for t in range(8)])
    cases = sum(o[5] for o in out)
    hits = sum(o[1] for o in out)
    minw = min(o[3] for o in out)
    record("S2 scan", None, f"staff bases={nb}, 255 XOR deltas, 8 beats, {cases:,} cases, {min(cpu,8)} workers")
    for beat, h, op, mw, hist, c in out:
        record("S2 scan", None, f"beat {beat}: cases={c:,} singletons={h} one_pair_both={op} "
                                f"min changed bytes after rehair={mw} weight_hist={hist[1:5]}")
    record("S2 scan", hits == 0, f"{hits} bow+rehair singletons in {cases:,} cases (all 8 beats); "
                                 f"minimum changed bytes = {minw}")

    # S3 forced-change sets
    rb = np.random.default_rng(4242).integers(0, 256, (1 << 12, 8))
    a0 = bow_s(rb)
    forced = {}
    for t in range(8):
        always = np.ones(8, bool)
        for d in range(1, 256):
            h = rb.copy()
            h[:, t] ^= d
            always &= (a0 != bow_s(h)).all(0)
        forced[t] = [int(c) for c in np.nonzero(always)[0]]
    record("S3 forced", None, f"bow outputs that always change, by input beat: {forced}")
    record("S3 forced", all(forced[k] == v for k, v in {0: [0, 1, 2], 4: [5, 6], 6: [5, 7], 7: [5]}.items()),
           "beat0->{0,1,2}, beat4->{5,6}, beat6->{5,7}, beat7->{5} reproduced (2 pairs => no singleton)")

    # S4 bow linear relations on the live layout
    X = np.random.default_rng(11).integers(0, 256, (1 << 21, 8))
    Y = bow_s(X)
    c2 = float((1 - 2 * ((X[:, 0] & 1) ^ ((X[:, 1] >> 7) & 1) ^ (Y[:, 0] & 1)).mean()))
    c1 = float((1 - 2 * ((X[:, 6] & 1) ^ ((Y[:, 7] >> 4) & 1)).mean()))
    record("S4 linear", None, f"bow 2-bit (c0b0^c1b7)->c0b0 corr={c2:+.4f}; c6b0->c7b4 corr={c1:+.4f}")
    record("S4 linear", abs(abs(c2) - 0.145) < 0.01 and abs(abs(c1) - 0.039) < 0.006,
           "bow-local linear relations reproduce; they stay inside the bow (capped by the rehair S-boxes)")

    # S6 LAT of every keyed table
    H = np.array([[1]], dtype=np.int64)
    for _ in range(8):
        H = np.block([[H, H], [H, -H]])
    par = np.array([bin(i).count("1") & 1 for i in range(256)])
    ar = np.arange(256)[None, :]
    lats = []
    for s in (sch, N.Schedule(SEED, bytes(16))):
        for k in s.rounds:
            for T in (k["S"], k["S2"]):
                F = 1 - 2 * par[np.asarray(T)[:, None] & ar]
                W = H @ F
                W[0, :] = 0
                W[:, 0] = 0
                lats.append(int(np.abs(W).max() // 2))
    record("S6 LAT", max(lats) == 16 and len(set(lats)) == 1,
           f"all {len(lats)} keyed tables: max |LAT| = {max(lats)}/256 = 2^-3, i.e. the SM4/inversion class")

    # S5 round-level differentials
    for rounds, npairs in ((1, 1 << 16), (2, 1 << 15), (3, 1 << 13)):
        rng = np.random.default_rng(1234 + rounds)
        x = rng.integers(0, 256, (npairs, 128))
        d = np.zeros(128, dtype=np.int64)
        d[int(rng.integers(0, 128))] = 1
        z = (C.enc(x, rounds, white=False) ^ C.enc(x ^ d, rounds, white=False)).astype(np.uint8)
        wts = np.unpackbits(z[:, :, None], axis=2).sum((1, 2))
        maxmult = max(collections.Counter(map(bytes, z)).values())
        cellprob = max(max(collections.Counter(z[:, c].tolist()).values()) for c in range(128)) / npairs
        record("S5 diff", None, f"{rounds} round(s), {npairs} chosen pairs: mean flipped bits "
                                f"{wts.mean():.1f}/1024 (random 512.0), max repeated output diff x{maxmult}, "
                                f"max single-cell diff prob {cellprob:.4f}")

    # S5b one-cell integral through 1 round
    x = np.random.default_rng(5).integers(0, 256, (256, 128))
    x[:, 0] = np.arange(256)
    y = C.enc(x, 1, white=False)
    zeros = int((np.bitwise_xor.reduce(y, axis=0) == 0).sum())
    record("S5b integ", None, f"1 round, full 256-value cell set: {zeros}/128 zero-sum output cells "
                              f"(random expectation ~0.5) -> no surviving integral at the round input")

    record("time", None, f"total {time.time()-t0:.1f}s")
    print("\n===== SUMMARY =====", flush=True)
    for sec, ok, msg in RESULTS:
        print(({True: "PASS", False: "FAIL", None: "INFO"}[ok]).ljust(4) + f" {sec:10} {msg}")
    fails = sum(1 for _, ok, _ in RESULTS if ok is False)
    print(f"\n{fails} failure(s). Verdict: " +
          ("no break found; results above are reproductions of the author's claims plus the implementation findings"
           if fails == 0 else "SEE FAILURES ABOVE"))


if __name__ == "__main__":
    main()
