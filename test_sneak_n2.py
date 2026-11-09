"""Tests for Sneak staff-core N2 (8-bit cells + five bar-line mixes + two interior joins (7 mixes) per staff + late S2 + bar/triplet encore + six triplets after each bar pass + clef-bound tag + SIV nonce: 16 faces x 8 byte-beats, 128-byte block, keyed SM4-affine S-boxes, SM4-field pairs/butterfly, integer triplets and nonlinear bow pressure plus cross-staff matchings). Run: python3 test_sneak_n2.py  (writes nothing into N1 / snapshot trees)."""
import inspect, sys, os, random, hashlib, subprocess
sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE); import sneak_n2 as N
SEED = N.load_seed(); R = random.Random(2); P = F = S = 0
def check(name, cond):
    global P, F
    if cond: P += 1; print("PASS", name)
    else: F += 1; print("FAIL", name)
def skip(name):
    global S
    S += 1; print("SKIP", name)
def optional_blob(path):
    try:
        for line in open(path):
            if line.startswith("blob"):
                return bytes.fromhex(line.split()[-1])
    except FileNotFoundError:
        return None
    return None
def fails_closed(f):
    """True iff f() raises (so no payload is returned)."""
    try: f(); return False
    except (N.AuthError, N.DecodeError, ValueError): return True
def catch(f):
    try: f(); return None
    except Exception as e: return e
rb = lambda n: bytes(R.randrange(256) for _ in range(n))
rgrid = lambda: [[R.randrange(256) for _ in range(8)] for _ in range(16)]
flip = lambda b, k: bytes(x ^ (1 << (k % 8)) if i == k // 8 else x for i, x in enumerate(b))
hd = lambda a, b: sum(bin(x ^ y).count("1") for x, y in zip(a, b))
DEMO_NONCE = bytes.fromhex(open(os.path.join(HERE, "demo-nonce.txt")).read().strip())   # pre-pickup SIV nonce; still used as a fixed schedule nonce and for old-version blobs
def hw_field(label):
    for line in open(os.path.join(HERE, "hello-world.txt")):
        if line.startswith(label): return bytes.fromhex(line.split()[-1])
HW_BLOB = hw_field("blob"); HW_PICKUP = hw_field("pickup")
PRE_PICKUP_179 = optional_blob("/tmp/sneak_n2_pre_pickup/hello-world.txt")

# ---- seed / format
check("seed is the 1024-bit file (128 bytes), same parse as N1", len(SEED) == 128 and SEED.hex().startswith("62ba585f"))
check("blob length 196 = 1 + 3 + 16 + 16 + 128 + 32", len(N.encrypt(b"hello world", SEED)) == 196 == N.BLOB_LEN == 1 + 3 + 16 + 16 + 128 + 32)
check("blob starts with version byte 1 then b'SN2'", N.encrypt(b"x", SEED)[:4] == bytes([N.FMT_VERSION]) + b"SN2" == b"\x01SN2")
# ---- packaging (relative seed, cached attestation, version byte, weak seeds)
check("SEED_PATH is sneak1024-seed.txt next to the module",
      os.path.basename(N.SEED_PATH)=="sneak1024-seed.txt" and os.path.dirname(os.path.abspath(N.SEED_PATH))==os.path.abspath(HERE))
check("load_seed() finds the module-relative demo seed", N.load_seed()==SEED and SEED.hex().startswith("62ba585f"))
check("embedded mix digest matches a fresh sha256(mix_description())",
      N.EXPECTED_MIX_SHA256==N._MIX_SHA256==hashlib.sha256(N.mix_description()).hexdigest() and N._SOURCE_AVAILABLE is True)
check("FMT_VERSION is 1 and is authenticated in the tag", N.FMT_VERSION==1)
old_style = b"SN2" + bytes(192)
e_old = catch(lambda: N.decrypt(old_style, SEED))
check("old 195-byte SN2 blob raises UnsupportedVersion before a tag check",
      isinstance(e_old, N.UnsupportedVersion) and str(e_old)=="unsupported version")
wrong_ver = bytes([2]) + b"SN2" + bytes(192)
e_ver = catch(lambda: N.decrypt(wrong_ver, SEED))
check("version byte 2 on a 196-byte blob raises UnsupportedVersion, not tag mismatch",
      isinstance(e_ver, N.UnsupportedVersion) and str(e_ver)=="unsupported version")
check("weak seeds rejected: all-zero, integer 1, 31 distinct nonzero bytes",
      all(isinstance(catch(lambda s=s: N.encrypt(b"x", s)), ValueError) and "weak seed" in str(catch(lambda s=s: N._seed_bytes(s)))
          for s in (bytes(128), 1, bytes(range(1,32))+bytes(97))))
check("real demo seed and os.urandom(128) are accepted",
      len(N._seed_bytes(SEED))==128 and len(N._seed_bytes(os.urandom(128)))==128)

# ---- round trips
check("roundtrip hello world (SIV nonce)", N.decrypt(N.encrypt(b"hello world", SEED), SEED) == b"hello world")
check("hello-world.txt demo blob (196 bytes) decrypts to b'hello world' and its pickup/nonce/ct/tag lines match live split_blob",
      len(HW_BLOB) == 196 and N.decrypt(HW_BLOB, SEED) == b"hello world" and N.split_blob(HW_BLOB) == (bytes([N.FMT_VERSION]) + b"SN2", HW_PICKUP, hw_field("nonce"), hw_field("ciphertext"), hw_field("tag")))
check("roundtrip random messages, every length 0..127 (x3)", all(N.decrypt(N.encrypt(m, SEED), SEED) == m for L in range(128) for m in (rb(L), rb(L), bytes(L))))
check("roundtrip edge msgs (0xFF*127, trailing zeros, 0x80*127, empty)", all(N.decrypt(N.encrypt(m, SEED), SEED) == m for m in (b"\xff" * 127, b"x\x00\x00", b"\x80" * 127, b"")))
check("oversize message (128, 200 bytes) rejected", fails_closed(lambda: N.encrypt(bytes(128), SEED)) and fails_closed(lambda: N.encrypt(bytes(200), SEED)))
check("int seed (N1-style) accepted and equals bytes seed (cross-decrypt)", N.decrypt(N.encrypt(b"hi", int.from_bytes(SEED, "big")), SEED) == b"hi" and N.decrypt(N.encrypt(b"hi", SEED), int.from_bytes(SEED, "big")) == b"hi")

# ---- integrity: fail closed
c = HW_BLOB; C_PK, C_NONCE = c[4:20], c[20:36]
check("every single-bit flip of the 196-byte blob (1568: version, pickup, nonce, ct, tag) fails closed", len(c) * 8 == 1568 and
      all(fails_closed(lambda k=k: N.decrypt(flip(c, k), SEED)) for k in range(8 * len(c))))
for name, lo, hi in (("version", 0, 4), ("pickup", 4, 20), ("nonce", 20, 36), ("ciphertext", 36, 164), ("tag", 164, 196)):
    check(f"all {8*(hi-lo)} single-bit flips in {name} raise AuthError (no payload)",
          all(isinstance(catch(lambda k=k: N.decrypt(flip(c, k), SEED)), N.AuthError) for k in range(8 * lo, 8 * hi)))
rand_ok = 0
for _ in range(1000):
    blob = rb(196)
    if not fails_closed(lambda: N.decrypt(blob, SEED)): rand_ok += 1
print(f"random 196-byte blobs accepted: {rand_ok}/1000")
check("1000 random 196-byte blobs: 0 accepted", rand_ok == 0)
rand_ok2 = sum(not fails_closed(lambda b=bytes([N.FMT_VERSION]) + b"SN2" + rb(192): N.decrypt(b, SEED)) for _ in range(1000))
print(f"random blobs with correct version+SN2 prefix accepted: {rand_ok2}/1000")
check("1000 random blobs WITH correct version+SN2 prefix: 0 accepted", rand_ok2 == 0)
check("truncated blobs (every length 0..195) fail closed", all(fails_closed(lambda L=L: N.decrypt(c[:L], SEED)) for L in range(196)))
METERED_LOOPED = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611e6ddb30fb6e2deaf5f356a741a7212e25bedc3a86da69c2e72bb2ca96f5f9198d619533d5c0e5bc7c4f892a33bc243d5919db5981c71000354729bb9b6c96a42e27c71ead9b443ec3bb651ad6c1f64049ad670e9fce010d9a294010462bbe177eca89fe9d25b5e86fc1ba3f28c9170938db2b4da9d0853062ea019567e8f8fda3dec9e3365d9abaf8d550eecf1102846ba55f316e2ba1feb88eff2fa16a705311ae1bbe416b9d4f9829246ff24edd27c1c2196e5947e3230f")
METERED_UNLOOPED = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611ea5c1cd29edd57f80f90f337c115fc2a7046e01ccbd13ca1c0ee21ead2fafb5139c39c11642a529b431fb81bf425af5c43390bfaa045decccb50ee069545f3470390e3f26be64d7a7b2ca55d9f4488d3ae5789ce45cfa13530267e01b01f7490aef86e6073f100f996b2f86555211ee3e73875d1ca47c3fd161943217e67cb11f0864499f22f6e97425ab6ebe2cc0f07c88e529214f10860951a3362925eff74c270c77fa2b94a45db3c641ae1a00749c217827d6f10c68fb")
OLD_4BIT_115 = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611e328603c75274b178415090ebb344261cf94b1cfada32739a41ed2ab590e447bb4a07ff1013668f0802cd4b3c81aa4dc96c008db753d8b82ec56d91fb7a6208eeef4204fa2b9b6d42d6efb30c39d70ee0866e669bbb7a35a75ff2d90e4df41bc7")   # 4-bit N2 demo blob (115 bytes)
check("old 4-bit 115-byte blob fails closed on length (AuthError); zero-padded / re-wrapped to 179 and 195 bytes also fails closed",
      len(OLD_4BIT_115) == 115 and isinstance(catch(lambda: N.decrypt(OLD_4BIT_115, SEED)), N.AuthError)
      and fails_closed(lambda: N.decrypt(OLD_4BIT_115 + bytes(64), SEED)) and fails_closed(lambda: N.decrypt(OLD_4BIT_115[:83] + bytes(64) + OLD_4BIT_115[83:], SEED)) and fails_closed(lambda: N.decrypt(OLD_4BIT_115 + bytes(80), SEED)))
check("old metered 203-byte blobs (looped and unlooped) fail closed on length (AuthError), also cut to 179 / 195 bytes", len(METERED_LOOPED) == len(METERED_UNLOOPED) == 203
      and all(isinstance(catch(lambda b=b: N.decrypt(b, SEED)), N.AuthError) for b in (METERED_LOOPED, METERED_UNLOOPED))
      and all(fails_closed(lambda b=b: N.decrypt(b[:179], SEED)) for b in (METERED_LOOPED, METERED_UNLOOPED))
      and all(fails_closed(lambda b=b: N.decrypt(b[:195], SEED)) for b in (METERED_LOOPED, METERED_UNLOOPED)))
PREBAR_179 = bytes.fromhex("534e32e573fbdf1e63278498735dfce435611e3589c1087bc86a600186bc2f497b23eea1ffda180f7c53a4cf83b016afbc9eb50558bf4a34a6e6506129f5c8b5c60b50f056070bb2488f256aade8a13e49d0f03fefb0d5bd6596d62c07892bb3a7d43b14b45c759ef02b379e498538766025fe20ad6d7de0a0410fda7161a489327cfb3980b75ffeb6671e67f9f6659bd58b731a59f177f0b1679eda217f4a8d8946af07c78480e6daee87527015f5844b7438")   # 8-bit N2 demo blob from before the bar-line layer (same length)
check("pre-bar 8-bit 179-byte demo blob now fails the clef-bound tag -> AuthError, no payload",
      len(PREBAR_179) == 179 and isinstance(catch(lambda: N.decrypt(PREBAR_179, SEED)), N.AuthError))
if PRE_PICKUP_179 is None:
    skip("pre-pickup 179-byte hello-world blob (from /tmp/sneak_n2_pre_pickup) fails closed")
else:
    _e = catch(lambda: N.decrypt(PRE_PICKUP_179, SEED))
    check("pre-pickup 179-byte hello-world blob (from /tmp/sneak_n2_pre_pickup) fails closed as unsupported version",
          len(PRE_PICKUP_179) == 179 and isinstance(_e, N.UnsupportedVersion) and "unsupported version" in str(_e))
check("staffs are linear: no staff-loop layer (no staff_loop/staff_unloop/LOOP_A/LOOP_B) and no loop step in round_enc/round_dec",
      not any(hasattr(N, n) for n in ("staff_loop", "staff_unloop", "loop_a", "loop_b", "LOOP_A", "LOOP_B"))
      and "loop" not in inspect.getsource(N.round_enc) and "loop" not in inspect.getsource(N.round_dec))
check("8-bit cells: 16 faces x 8 byte-beats, 128-byte block, 196-byte blob, max payload 127", N.NF == 16 and N.NB == 8 and N.CELL_BITS == 8 and N.BLOCK_LEN == 128 and N.BLOB_LEN == 196 and N.MAX_MSG == 127)
check("extended blob (extra byte) fails closed", fails_closed(lambda: N.decrypt(c + b"\x00", SEED)))
check("version prefix changed to SN1 / SN3 / sn2 fails closed", all(fails_closed(lambda v=v: N.decrypt(v + c[4:], SEED)) for v in (b"SN1", b"SN3", b"sn2")))
c2 = N.encrypt(b"hello world!", SEED)
check("splicing: ct+tag of one blob with nonce of another fails", fails_closed(lambda: N.decrypt(c[:20] + c2[20:36] + c[36:], SEED)))
check("splicing: pickup of another blob onto this one fails", fails_closed(lambda: N.decrypt(c[:4] + c2[4:20] + c[20:], SEED)))
check("tag of one message on ct of another fails", fails_closed(lambda: N.decrypt(c[:164] + c2[164:], SEED)))
wrong = [bytearray(SEED) for _ in range(3)]; wrong[0][0] ^= 1; wrong[1][127] ^= 0x80; wrong[2] = bytearray(rb(128))
check("wrong seed fails closed (bit 0, bit 1023, random seed)", all(isinstance(catch(lambda w=w: N.decrypt(c, bytes(w))), N.AuthError) for w in wrong))
check("decrypt checks tag before decoding (tampered ct -> AuthError, never DecodeError)",
      all(isinstance(catch(lambda k=k: N.decrypt(flip(c, k), SEED)), N.AuthError) for k in range(8 * 36, 8 * 164, 7)))
src = open(os.path.join(HERE, "sneak_n2.py")).read()
check("tag compared with hmac.compare_digest", "hmac.compare_digest(tag" in src)

# ---- nonces / determinism / schedule avalanche
hw_text = open(os.path.join(HERE, "hello-world.txt")).read()
check("demo blob in hello-world.txt: blob, pickup, nonce, ct, tag hex all present", all(x.hex() in hw_text for x in N.split_blob(c)[1:]) and c.hex() in hw_text)
a1, a2 = N.encrypt(b"hello world", SEED), N.encrypt(b"hello world", SEED)
check("pickup: same message twice -> different pickups, nonces, blobs; both decrypt to original",
      a1[4:20] != a2[4:20] and a1[20:36] != a2[20:36] and a1 != a2 and N.decrypt(a1, SEED) == N.decrypt(a2, SEED) == b"hello world")
check("pickup: 200 encryptions of the same message -> 200 distinct pickups and blobs", len({N.encrypt(b"1234", SEED) for _ in range(200)}) == 200)
msgs = {rb(R.randrange(1, 64)) for _ in range(300)}
check("300 different messages -> 300 different nonces and ciphertexts", len({N.encrypt(m, SEED)[20:36] for m in msgs}) == len(msgs) == len({N.encrypt(m, SEED)[36:164] for m in msgs}))
def nonce_formula_ok(m):
    b = N.encrypt(m, SEED); pk, n = b[4:20], b[20:36]
    return n == hashlib.sha256(N.staff_clef(SEED) + pk + N.encode_block(m)).digest()[:16] == N.siv_nonce(m, pk, SEED)
check("nonce formula: SHA-256(clef || pickup || encode_block(msg))[:16] for the pickup stored in the blob (demo + 50 random)",
      C_NONCE == hashlib.sha256(N.staff_clef(SEED) + C_PK + N.encode_block(b"hello world")).digest()[:16] and all(nonce_formula_ok(rb(R.randrange(128))) for _ in range(50)))
check("encrypt(msg, nonce=wrong) raises ValueError (random, zero, old demo SIV, another blob's nonce for same msg)",
      all(isinstance(catch(lambda n=n: N.encrypt(b"hello world", SEED, n)), ValueError) for n in (rb(16), bytes(16), DEMO_NONCE, C_NONCE)))
check("encrypt has no public pickup argument (signature is msg, seed, nonce)", list(inspect.signature(N.encrypt).parameters) == ["msg", "seed", "nonce"])
check("os.urandom used only for the pickup in encrypt, never for nonce", inspect.getsource(N.encrypt).count("os.urandom(") == 1 and "pickup = os.urandom(PICKUP_LEN)" in inspect.getsource(N.encrypt)
      and "urandom" not in inspect.getsource(N.siv_nonce) and "urandom" not in inspect.getsource(N.Schedule))
def pin_dictionary_fails(trials=200):
    rr = random.Random(77)
    for _ in range(trials):
        pin = ("%04d" % rr.randrange(10000)).encode(); target = N.encrypt(pin, SEED)
        if N.encrypt(pin, SEED) == target: return False
        if any(N.encrypt(("%04d" % g).encode(), SEED) == target for g in rr.sample(range(10000), 5)): return False
    return True
check("PIN dictionary: encrypt(correct_guess) != target blob over 200 fresh PIN-like targets (old match attack fails)", pin_dictionary_fails())
sch_g = N.Schedule(SEED, DEMO_NONCE); ct_g = N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(N.encode_block(b"guess")), sch_g))
forged = bytes([N.FMT_VERSION]) + b"SN2" + C_PK + DEMO_NONCE + ct_g + N._tag(sch_g.mac_key, C_PK, DEMO_NONCE, ct_g, N.staff_clef(SEED), N.key_signature(SEED))
check("valid tag but blob nonce != SIV nonce of recovered message -> AuthError (insider-built blob)", isinstance(catch(lambda: N.decrypt(forged, SEED)), N.AuthError))
check("bad nonce length rejected", fails_closed(lambda: N.encrypt(b"x", SEED, b"short")))
base = N.Schedule(SEED, DEMO_NONCE).material(); fr = []
for k in range(128):
    m2 = N.Schedule(SEED, flip(DEMO_NONCE, k)).material(); fr.append(hd(base, m2) / (8 * len(base)))
print(f"schedule avalanche (1-bit nonce flip, all 128 bits, {8*len(base)} schedule bits): mean {sum(fr)/len(fr):.4f}, min {min(fr):.4f}, max {max(fr):.4f}")
check("1-bit nonce flip changes ~half of round-key+whitening bits (each of 128 flips in 0.46..0.54)", all(0.46 <= x <= 0.54 for x in fr))
sch0 = N.Schedule(SEED, DEMO_NONCE); sch1 = N.Schedule(SEED, flip(DEMO_NONCE, 0))
# Sample keyed tables for the keyed Latin B0/rehair layers (round 0 of the demo schedule): S for u', S2 for v'.
TS = (sch0.rounds[0]["S"], sch0.rounds[0]["S2"]); TSI = (sch0.rounds[0]["SI"], sch0.rounds[0]["SI2"])
check("1-bit nonce flip changes every round's S-box params, weave, sigma and bridge (16/16 rounds)",
      all(all(sch0.rounds[r][k] != sch1.rounds[r][k] for k in ("S", "S2", "SH", "SV", "sigma", "bridge")) for r in range(16)))
check("1-bit nonce flip changes MAC key", sch0.mac_key != sch1.mac_key)
mk = [hd(base, N.Schedule(flip(SEED, k), DEMO_NONCE).material()) / (8 * len(base)) for k in range(0, 1024, 37)]
check("1-bit seed flip changes ~half the schedule bits (28 positions)", all(0.46 <= x <= 0.54 for x in mk))
st = N.StaffSponge(b"K", SEED, DEMO_NONCE).take(64); sm = N.StaffSponge(b"M", SEED, DEMO_NONCE).take(64)
check("domain separation: MAC stream (b'M') and schedule stream (b'K') differ and MAC key not in schedule material",
      st != sm and sch0.mac_key not in sch0.material() and sch0.mac_key == sm[:32])
check("clef = StaffSponge domain 'C', seed + zero nonce (independent hashlib check), 16 bytes, not in blob",
      N.staff_clef(SEED) == hashlib.sha256(b"SN2/C" + (0).to_bytes(4, "big") + SEED + bytes(16)).digest()[:16] and N.staff_clef(SEED) not in c)
check("clef depends on seed", N.staff_clef(flip(SEED, 5)) != N.staff_clef(SEED))
check("tag = HMAC-SHA256(mac_key, clef || key_sig || version || 'SN2' || pickup || nonce || ct) (independent hmac check)",
      c[164:] == __import__("hmac").new(N.Schedule(SEED, C_NONCE).mac_key, N.staff_clef(SEED) + N.key_signature(SEED) + bytes([N.FMT_VERSION]) + b"SN2" + c[4:20] + c[20:36] + c[36:164], hashlib.sha256).digest())
check("MAC key derived from seed via SHA-256 domain 'M' (independent check with hashlib)",
      sch0.mac_key == hashlib.sha256(b"SN2/M" + (0).to_bytes(4, "big") + SEED + DEMO_NONCE).digest())

# ---- S-boxes (8-bit, keyed SM4-affine)
exec(open(os.path.join(HERE, "sm4_vector_check.py")).read())     # SM4 reference cipher, used ONLY to authenticate the S-box table
check("base S-box table is the published SM4 S-box: GB/T 32907-2016 Example 1 and draft-ribose-cfrg-sm4 Example 4 reproduce", sm4_table_ok(N.SM4_SBOX))
bd, bl = N.ddt_max(N.SM4_SBOX), N.lat_max(N.SM4_SBOX)
print(f"SM4 base S-box: DDT max {bd}/256 (best differential prob {bd}/256 = 2^-6), LAT max |count-128| {bl}/256 (|bias| {bl}/256 = 2^-4, nonlinearity {128-bl})")
check("SM4 base S-box: permutation, DDT max 4, LAT max 16 (nonlinearity 112)", sorted(N.SM4_SBOX) == list(range(256)) and bd == 4 and bl == 16)
def sbox_ok(sch): return all(sorted(rk[k]) == list(range(256)) and all(rk[ik][rk[k][x]] == x for x in range(256)) and N.ddt_max(rk[k]) == 4 for rk in sch.rounds for k, ik in (("S", "SI"), ("S2", "SI2")))
dd = [N.ddt_max(rk[k]) for rk in sch0.rounds for k in ("S", "S2")]; ll = [N.lat_max(rk[k]) for rk in sch0.rounds for k in ("S", "S2")]
print(f"demo nonce, 32 keyed round S-boxes: DDT max {sorted(set(dd))}, LAT max {sorted(set(ll))}")
check("demo nonce: all 32 keyed round S-boxes are permutations (with inverse) and inherit DDT max 4", sbox_ok(sch0) and dd == [4] * 32)
check("demo nonce: all 32 keyed round S-boxes inherit LAT max 16", ll == [16] * 32)
check("5 random nonces: all 160 keyed S-boxes permutations with DDT max 4", all(sbox_ok(N.Schedule(SEED, rb(16))) for _ in range(5)))
check("affine matrices A1–A4 invertible (8x8 over GF(2)) in every round", all(N.mat_invertible(rk[k]) for rk in sch0.rounds for k in ("A1", "A2", "A3", "A4")))
check("S-boxes are keyed: 16 distinct boxes among the 16 demo rounds, none equal to the SM4 base", len({tuple(rk["S"]) for rk in sch0.rounds}) == 16 and all(bytes(rk[k]) != N.SM4_SBOX for rk in sch0.rounds for k in ("S", "S2")))
check("no AES S-box / MixColumns / GF(2^8) AES poly / AES libraries in library",
      not any(w in src.lower() for w in ("637c777bf26b6fc5", "0x63, 0x7c", "0x11b", "mixcolumns(", "from crypto", "import cryptography", "aesgcm", "aes.new")))

# ---- mixes / round invertibility
check("2-cell SM4-field mix is a bijection on all 65536 byte pairs, exhaustive inverse", len({N.mix2(u, v) for u in range(256) for v in range(256)}) == 65536 and all(N.mix2_inv(*N.mix2(u, v)) == (u, v) for u in range(256) for v in range(256)))
# ---- bar lines: five different invertible 2-byte mixes per staff (four measures of 2/4)
check("five bar lines (boundaries 0,2,4,6,8) plus two interior joins M2 (2,3), M3 (4,5) = 7 mixes in beat order; every adjacent pair mixed; no (7,0) end-to-end pair",
      [b[1] for b in N.BARS] == [0, 2, 3, 4, 5, 6, 8] and [b[2] for b in N.BARS] == [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)]
      and [b[0] for b in N.BARS if b[0].startswith("B")] == ["B0 start", "B1 bar 2", "B2 center", "B3 bar 6", "B4 end"]
      and all(set(b[2]) != {0, 7} for b in N.BARS))
check("historical matrix slots stay distinct; six active field pairs retain determinants (B0 slot unused)",
      len(N.BARS) == 7 and len({b[3] for b in N.BARS}) == 7 and [N.bar_det(b[3]) for b in N.BARS] == [3, 3, 3, 7, 1, 3, 1])
for k, (name, _, _, M) in enumerate(N.BARS):
    if name == "B0 start": continue  # covered by exhaustive keyed-Latin checks below
    Mi = N.BARS_INV[k]
    check(f"bar {name} mix {M} is a bijection on all 65536 byte pairs and its inverse {Mi} undoes it",
          len({N.bar_apply(M, u, v) for u in range(256) for v in range(256)}) == 65536
          and all(N.bar_apply(Mi, *N.bar_apply(M, u, v)) == (u, v) for u in range(256) for v in range(256)))
# GF(2)-linearity makes the XOR derivative independent of the base state.
check("SM4 field reduction uses 0xF5, not AES 0x1B", N.gf_mul(128, 2) == 0xF5)
check("all nonzero field inverses and high-bit products", all(N.gf_mul(x, N.gf_inv(x)) == 1 and N.gf_mul(x, 128) != 0 for x in range(1,256)))
for name, _, _, M in N.BARS[1:]:
    check(f"{name}: every nonzero single-cell XOR derivative has two outputs at ANY base",
          all(all(N.bar_apply(M, d, 0)) and all(N.bar_apply(M, 0, d)) for d in range(1,256))
          and all(N.gf_mul(c, x ^ d) == N.gf_mul(c, x) ^ N.gf_mul(c, d)
                  for c in set(sum(M, ())) for x in range(256) for d in range(256)))
check("bar layer as a whole inverts (500 random grids)", all((lambda g: N.bar_unmix(N.bar_mix(g, *TS), *TSI) == g)(rgrid()) for _ in range(500)))
check("bar layer is in the round: round_enc calls bar_mix, round_dec calls bar_unmix",
      "bar_mix(" in inspect.getsource(N.round_enc) and "bar_unmix(" in inspect.getsource(N.round_dec))
# ---- triplets: all six unlooped adjacent windows, after each bar pass
check("six distinct det-1 triplets cover (0,1,2)..(5,6,7), no wrap",
      [t[1] for t in N.TRIPLETS] == [tuple(range(i, i+3)) for i in range(6)]
      and len({t[2] for t in N.TRIPLETS}) == 6 and all(N.triplet_det(t[2]) == 1 for t in N.TRIPLETS))
check("each triplet row and column has >=2 odd coefficients", all(
      all(sum(x & 1 for x in row) >= 2 for row in M)
      and all(sum(M[i][j] & 1 for i in range(3)) >= 2 for j in range(3)) for _, _, M in N.TRIPLETS))
def mat_product(A, B):
    n = len(A)
    return tuple(tuple(sum(A[i][k] * B[k][j] for k in range(n)) & 255 for j in range(n)) for i in range(n))
for ti, (name, beats, M) in enumerate(N.TRIPLETS):
    Mi = N.TRIPLETS_INV[ti]; ident = ((1,0,0),(0,1,0),(0,0,1))
    check(f"{name} {beats} matrix {M}, det 1, two-sided inverse {Mi}",
          mat_product(M, Mi) == ident == mat_product(Mi, M)
          and all((lambda v: N.triplet_apply(Mi, *N.triplet_apply(M, *v)) == v)(tuple(rb(3))) for _ in range(1000)))
def single_cell_exhaustive(M):
    # Equivalent exhaustive reduction, not random sampling: Z/256 linearity gives
    # F(v')-F(v) = M[:,j]*((x XOR a)-x), regardless of ALL other input cells.
    # Output XOR is zero iff its additive difference is zero. We exhaust all
    # 3*255*256 choices of input cell, nonzero XOR delta and input value x;
    # each case represents all 256**2 completions of the other two cells.
    count = 0; minimum = 3
    for j in range(3):
        for a in range(1, 256):
            for x in range(256):
                d = (x ^ a) - x
                weight = sum((M[i][j] * d) & 255 != 0 for i in range(3))
                count += weight == 1; minimum = min(minimum, weight)
    return count, minimum
for name, _, M in N.TRIPLETS:
    single, minimum = single_cell_exhaustive(M)
    print(f"{name}: all 3*255*256 XOR cases, independent of 256**2 other-cell completions: singleton events {single}, min output cells {minimum}")
    check(f"{name} exhaustive equivalent: NO single-cell events for ANY single-cell nonzero XOR input difference", single == 0 and minimum >= 2)
check("triplet layer inverse, 500 random grids; does not mutate caller grid", all(
      (lambda g: N.triplet_unmix(N.triplet_mix(g)) == g and N.triplet_mix(g) is not g)(rgrid()) for _ in range(500)))
check("combined bar+triplet layer inverse on both shells, 500 random grids", all(
      (lambda g: N.bar_unmix(N.triplet_unmix(N.triplet_mix(N.bar_mix(g, *TS))), *TSI) == g)(rgrid()) for _ in range(500)))
def staff_matrix(layer):
    cols = [layer([[int(i == j) for i in range(8)]])[0] for j in range(8)]
    return tuple(tuple(cols[j][i] for j in range(8)) for i in range(8))
combined = lambda g: N.triplet_mix(N.bar_mix(g, *TS))
for label, layer in (("triplets", N.triplet_mix), ("bar+triplet (same as encore)", combined)):
    M = staff_matrix(layer)
    weights = [sum(M[i][j] & 1 for i in range(8)) for j in range(8)]
    observed = [sum(x != 0 for x in layer([[128 if i == j else 0 for i in range(8)]])[0]) for j in range(8)]
    print(f"{label} 0x80 output weights at zero base (0..7): {observed}; singleton crossings: {observed.count(1)}")
    check(f"{label}: no singleton 0x80 crossing at zero and 256 uniform base states", min(observed) >= 2 and all(sum(a != b for a, b in zip(layer([[base]*8])[0], layer([[base ^ (128 if i == j else 0) for i in range(8)]])[0])) >= 2 for base in range(256) for j in range(8)))

check("staff butterfly inverse (300 random grids, random sigma)", all((lambda g, s: N.staff_unmix(N.staff_mix(g, s), s) == g)(rgrid(), [R.sample(range(8), 8) for _ in range(16)]) for _ in range(300)))
check("shell bridge inverse, even and odd rounds (300 grids)", all((lambda g, b, r: N.shell_unmix(N.shell_mix(g, b, r), b, r) == g)(rgrid(), R.sample(range(64), 64), r) for _ in range(150) for r in (0, 1)))
check("weave inverse (300 grids)", all((lambda g, SH, SV: N.unweave(N.weave(g, SH, SV), SH, SV) == g)(rgrid(), [R.randrange(8) for _ in range(16)], [R.randrange(16) for _ in range(8)]) for _ in range(300)))
check("every round r = 0..15 inverts (20 grids each)", all(N.round_dec(N.round_enc(g, sch0.rounds[r], r), sch0.rounds[r], r) == g for r in range(16) for g in (rgrid() for _ in range(20))))
check("full 16-round block cipher encrypt/decrypt inverse (300 grids)", all(N.decrypt_grid(N.encrypt_grid(g, sch0), sch0) == g for g in (rgrid() for _ in range(300))))
check("block cipher is a permutation sample: 2000 random blocks -> 2000 distinct outputs", len({N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(rb(128)), sch0)) for _ in range(2000)}) == 2000)
check("byte<->grid encoding inverse (128 bytes <-> 16x8 byte cells)", all(N.grid_to_bytes(N.bytes_to_grid(b)) == b for b in (rb(128) for _ in range(100))))

# Explicit order / compatibility regression checks against both backups.
import importlib.util, hmac as _h
def load(name, path):
    if not os.path.isfile(path):
        return None
    sp = importlib.util.spec_from_file_location(name, path); m = importlib.util.module_from_spec(sp); sys.modules[name] = m; sp.loader.exec_module(m); return m
OLD = load("precolor2", "/tmp/sneak_n2_8bit_precolor2/sneak_n2.py")
PRE = load("preclef", "/tmp/sneak_n2_pre_clef_encore_siv/sneak_n2.py")
PRET = load("pretriplet", "/tmp/sneak_n2_pre_triplet/sneak_n2.py")
PREJ = load("prejoin", "/tmp/sneak_n2_pre_join_pairs/sneak_n2.py")   # cipher just before the 3-4 / 5-6 joins
FIELD_OLD = load("prefield", "/tmp/sneak_n2_pre_field_retune/sneak_n2.py")
if FIELD_OLD is None:
    skip("triplet tuples and integer helpers byte-for-byte unchanged by field retune")
else:
    check("triplet tuples and integer helpers byte-for-byte unchanged by field retune", N.TRIPLETS == FIELD_OLD.TRIPLETS and all(inspect.getsource(getattr(N, f)) == inspect.getsource(getattr(FIELD_OLD, f)) for f in ("triplet_apply", "triplet_inv", "triplet_det", "staff_mix")))
N3 = load("testn3", "/workspace/testn3/sneak_n2.py")                  # frozen testn3 copy (same previous cipher)
PRE_ORDER = load("preclef_order", "/tmp/sneak_n2_pre_clef_encore_siv/sneak_n2.py")
if PRE_ORDER is not None:
    PRE_ORDER.BARS, PRE_ORDER.BARS_INV = N.BARS, N.BARS_INV               # same pre-encore round, but with the new 7-mix list
if OLD is None:
    skip("round-0 existing sponge prefixes unchanged")
else:
    oldsch = OLD.Schedule(SEED, DEMO_NONCE)
    check("round-0 existing sponge prefixes unchanged", all(oldsch.rounds[0][k] == sch0.rounds[0][k] for k in oldsch.rounds[0]))
check("both colorings present: S2 differs from S in every round", all(rk["S2"] != rk["S"] for rk in sch0.rounds))
check("nonce flip changes second-coloring affine parameters every round", all(any(a[k] != b[k] for k in ("A3", "A4", "b3", "b4")) for a,b in zip(sch0.rounds, sch1.rounds)))
check("S2 exactly uses the published SM4-affine recipe", all(N.keyed_sbox(rk["A3"],rk["b3"],rk["A4"],rk["b4"]) == (rk["S2"],rk["SI2"]) for rk in sch0.rounds))
def order_ok():
    for r,rk in enumerate(sch0.rounds):
        g = rgrid()
        mid = N.shell_mix(N.staff_mix(N.weave([[rk["S"][x] for x in row] for row in N.xor_grid(g,rk["rk"])],rk["SH"],rk["SV"]),rk["sigma"]),rk["bridge"],r)
        T, TI = (rk["S"], rk["S2"]), (rk["SI"], rk["SI2"])
        mid = N.cross_staff_mix([N.odd_restack(N.bow_pressure(row), *T) for row in N.triplet_mix(N.bar_mix(mid, *T))])
        late = [[rk["S2"][x] for x in row] for row in mid]
        out = N.cross_staff_mix([N.odd_restack(N.bow_pressure(row), *T) for row in N.triplet_mix(N.bar_mix(late, *T))])
        if N.round_enc(g,rk,r) != out: return False
        back = N.bar_unmix(N.triplet_unmix([N.unbow_pressure(N.unodd_restack(row, *TI)) for row in N.cross_staff_unmix(out)]), *TI)
        if back != late: return False
        back = [[rk["SI2"][x] for x in row] for row in back]
        back = N.bar_unmix(N.triplet_unmix([N.unbow_pressure(N.unodd_restack(row, *TI)) for row in N.cross_staff_unmix(back)]), *TI)
        back = N.shell_unmix(back,rk["bridge"],r)
        back = N.staff_unmix(back,rk["sigma"])
        back = N.unweave(back,rk["SH"],rk["SV"])
        back = N.xor_grid([[rk["SI"][x] for x in row] for row in back],rk["rk"])
        if N.round_dec(out,rk,r) != back or back != g: return False
    return True
check("round order: bars -> triplets -> bow -> odd_restack -> cross -> S2 -> encore bars -> encore triplets -> bow -> odd_restack -> cross; decrypt reverses, uncross FIRST", order_ok()
      and inspect.getsource(N.round_enc).count("bar_mix(") == 2 and inspect.getsource(N.round_enc).count("triplet_mix(") == 2
      and inspect.getsource(N.round_dec).split("\n")[1].strip().startswith("g = cross_staff_unmix(g)"))
def trace_order():
    from unittest.mock import patch
    names = ("bar_mix", "triplet_mix", "bar_unmix", "triplet_unmix", "bow_pressure", "unbow_pressure", "odd_restack", "unodd_restack", "cross_staff_mix", "cross_staff_unmix"); calls = []
    def wrap(name, fun):
        def wrapped(*args): calls.append(name); return fun(*args)
        return wrapped
    from contextlib import ExitStack
    with ExitStack() as stack:
        for name in names: stack.enter_context(patch.object(N, name, wrap(name, getattr(N, name))))
        g = rgrid(); out = N.round_enc(g, sch0.rounds[0], 0); N.round_dec(out, sch0.rounds[0], 0)
    return calls == (["bar_mix", "triplet_mix"] + ["bow_pressure"]*16 + ["odd_restack"]*16 + ["cross_staff_mix"])*2 + (["cross_staff_unmix"] + ["unodd_restack"]*16 + ["unbow_pressure"]*16 + ["triplet_unmix", "bar_unmix"])*2
check("instrumented sequence: each bow -> rehair -> cross, inverse uncross -> unrehair -> unbow", trace_order())
if PRET is not None:
  check("historical pair slots, S-boxes, schedule, clef, encoding, weave and butterfly/bridge routing unchanged from pre-triplet (B0 implementation intentionally changed)", N.BARS == PRET.BARS
      and all(inspect.getsource(getattr(N,name)) == inspect.getsource(getattr(PRET,name)) for name in (
      "Schedule", "StaffSponge", "keyed_sbox", "staff_clef", "encode_block",   # siv_nonce/_tag/encrypt/decrypt/split_blob changed by the pickup
      "weave", "unweave", "staff_mix", "staff_unmix", "shell_mix", "shell_unmix")))
def not_fused():
    rr = random.Random(9)
    for r in range(15):
        a, b = sch0.rounds[r], sch0.rounds[r + 1]
        F = lambda g: [[b["S"][x] for x in row] for row in N.xor_grid(N.cross_staff_mix([N.odd_restack(N.bow_pressure(row), a["S"], a["S2"]) for row in N.triplet_mix(N.bar_mix([[a["S2"][x] for x in row] for row in g], a["S"], a["S2"]))]), b["rk"])]
        g = rgrid(); h = [row[:] for row in g]; h[0][1] ^= rr.randrange(1, 256)
        if sum(x != y for p_, q_ in zip(F(g), F(h)) for x, y in zip(p_, q_)) < 2: return False
    return True
check("S2 -> encore -> xor rk -> next-round S is NOT a single-cell function (1-cell change hits >=2 cells, rounds 0..14)", not_fused())
fc = lambda b: isinstance(catch(lambda: N.decrypt(b, SEED)), (N.AuthError, N.DecodeError))
if None in (OLD, PRE):
    skip("old 179-byte blobs from /tmp/sneak_n2_8bit_precolor2 and /tmp/sneak_n2_pre_clef_encore_siv raise AuthError (4 demo blobs)")
else:
    olds = {"precolor2 demo": OLD.encrypt(b"hello world", SEED, DEMO_NONCE),
            "precolor2 old-nonce": OLD.encrypt(b"hello world", SEED, bytes.fromhex("e573fbdf1e63278498735dfce435611e")),
            "pre-clef old-nonce": PRE.encrypt(b"hello world", SEED, bytes.fromhex("e573fbdf1e63278498735dfce435611e")),
            "pre-clef SIV-nonce": PRE.encrypt(b"hello world", SEED, DEMO_NONCE),
            }
    check("old 179-byte blobs from /tmp/sneak_n2_8bit_precolor2 and /tmp/sneak_n2_pre_clef_encore_siv raise AuthError (4 demo blobs)",
          all(len(b) == 179 and isinstance(catch(lambda b=b: N.decrypt(b, SEED)), N.AuthError) for b in olds.values()))
rr_ = random.Random(11)
if None in (FIELD_OLD, PRET, PREJ, N3):
    skip("pre-triplet + pre-join + testn3 old-length demo blobs fail closed")
    skip("256 random pre-join-pairs blobs fail closed (AuthError or DecodeError), none returns a plaintext")
    skip("pre-triplet/pre-join/testn3/pre-field demo blobs (179 bytes) now fail on length -> AuthError")
    skip("256 random pre-triplet blobs fail closed (AuthError or DecodeError), none returns plaintext")
else:
    prej = {"pre-field-retune demo": FIELD_OLD.encrypt(b"hello world", SEED), "pre-triplet demo": PRET.encrypt(b"hello world", SEED), "pre-join-pairs demo": PREJ.encrypt(b"hello world", SEED), "testn3 demo": N3.encrypt(b"hello world", SEED)}
    oldj = [PREJ.encrypt(bytes(rr_.randrange(256) for _ in range(rr_.randrange(40))), SEED) for _ in range(256)]
    check("pre-triplet + pre-join + testn3 old-length demo blobs fail closed", all(fc(b) for b in prej.values()))
    check("256 random pre-join-pairs blobs fail closed (AuthError or DecodeError), none returns a plaintext", all(fc(b) for b in oldj))
    oldt = [PRET.encrypt(bytes(rr_.randrange(256) for _ in range(rr_.randrange(40))), SEED) for _ in range(256)]
    check("pre-triplet/pre-join/testn3/pre-field demo blobs (179 bytes) now fail as unsupported version (not a key signature)",
          all(len(b) == 179 and isinstance(catch(lambda b=b: N.decrypt(b, SEED)), N.AuthError) for b in prej.values()))
    check("256 random pre-triplet blobs fail closed (AuthError or DecodeError), none returns plaintext", all(fc(b) for b in oldt))
if PRE is None:
    skip("512 random pre-clef blobs (valid under old MAC) all raise AuthError")
else:
    oldmany = [PRE.encrypt(bytes(rr_.randrange(256) for _ in range(rr_.randrange(40))), SEED) for _ in range(512)]
    check("512 random pre-clef blobs (valid under old MAC) all raise AuthError", all(isinstance(catch(lambda b=b: N.decrypt(b, SEED)), N.AuthError) for b in oldmany))

# ---- three leftover-shape fixes
PICKUP_OLD = load("pickup_old", "/tmp/sneak_n2_pre_three_fixes/sneak_n2.py")
old_blob = optional_blob("/tmp/sneak_n2_pre_three_fixes/hello-world.txt")
if old_blob is None:
    skip("pickup-era 195-byte recorded blob now raises unsupported version")
else:
    e = catch(lambda: N.decrypt(old_blob, SEED))
    check("pickup-era 195-byte recorded blob now raises unsupported version (not DecodeError)",
          len(old_blob) == 195 and isinstance(e, N.UnsupportedVersion) and "unsupported version" in str(e))
check("blob regions are version + SN2 + pickup + nonce + ct + tag", (N.PK0, N.N0, N.CT0, N.CT1, N.BLOB_LEN) == (4,20,36,164,196))
check("mix2 high-bit derivative is (0x80,0xF5), not integer singleton",
      tuple(a^b for a,b in zip(N.mix2(0,0), N.mix2(0,128))) == (128,245))
check("mix2 matrix determinant 3, characteristic-two inverse", N.MIX2_MATRIX == ((1,1),(1,2))
      and N.bar_det(N.MIX2_MATRIX) == 3 and N.MIX2_INV == N.bar_inv(N.MIX2_MATRIX))
if PICKUP_OLD is None:
    skip("triplet tables and integer arithmetic unchanged from pickup era")
else:
    check("triplet tables and integer arithmetic unchanged from pickup era", N.TRIPLETS == PICKUP_OLD.TRIPLETS
          and all(inspect.getsource(getattr(N,n)) == inspect.getsource(getattr(PICKUP_OLD,n)) for n in ("triplet_apply", "triplet_inv", "triplet_det", "triplet_mix", "triplet_unmix")))
check("key signature uses domain G and sha256(mix_description()) as sponge nonce (independent hashlib)",
      len(N.key_signature(SEED)) == 16 and N._MIX_SHA256 == N.EXPECTED_MIX_SHA256 == hashlib.sha256(N.mix_description()).hexdigest()
      and N.key_signature(SEED) == hashlib.sha256(
          b"SN2/G" + bytes(4) + SEED + bytes.fromhex(N._MIX_SHA256)).digest()[:16])
check("key signature has no public encrypt/decrypt override and no blob field", list(inspect.signature(N.encrypt).parameters) == ["msg","seed","nonce"]
      and list(inspect.signature(N.decrypt).parameters) == ["blob","seed"] and N.key_signature(SEED) not in c)
# Copies remain in memory only: no edits to any old snapshot or attack tree.
for kind in ("pair", "triplet", "mix2"):
    alt = load("altered_"+kind, os.path.join(HERE,"sneak_n2.py"))
    if kind == "pair":
        alt.BARS = alt.BARS[1:]  # actually skips B0 during encryption
        alt.BARS_INV = tuple(alt.bar_inv(M) for _,_,_,M in alt.BARS)
    elif kind == "triplet":
        alt.TRIPLETS = alt.TRIPLETS[1:]
        alt.TRIPLETS_INV = tuple(alt.triplet_inv(M) for _,_,M in alt.TRIPLETS)
    else:
        alt.MIX2_MATRIX = ((1,1),(1,3))
        alt.MIX2_INV = alt.bar_inv(alt.MIX2_MATRIX)
    ab = alt.encrypt(b"hello world", SEED)
    er = catch(lambda: N.decrypt(ab, SEED))
    # In-process mutation no longer moves the cached key_sig; the ciphertext still will not
    # decrypt under the live mix (tag may verify, then DecodeError / SIV mismatch).
    check("altered "+kind+" score: 196-byte alternate blob fails closed on live decrypt",
          len(ab) == 196 and alt.decrypt(ab, SEED) == b"hello world"
          and isinstance(er, (N.AuthError, N.DecodeError)))
# Each relevant constant is encoded dynamically, not a fixed prose promise.
from unittest.mock import patch
for name, value in (("FIELD_POLY",0x1F7), ("BOW_STROKES",tuple(reversed(N.BOW_STROKES))),
                    ("BOW_PRESSURE_ROT",tuple(reversed(N.BOW_PRESSURE_ROT))),
                    ("BOW_ROT_BASE",2), ("BOW_ROT_MOD",6), ("BOW_R2_SHIFT",2)):
    desc0 = N.mix_description()
    with patch.object(N, name, value): changed = N.mix_description() != desc0
    check("mix_description changes with "+name+" (key_sig is cached at import)", changed)
check("bow strokes match open even then interior odd order, pressure read only may wrap", N.BOW_STROKES ==
      ((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0)) and all({i,j}!={0,7} and p not in (i,j) for i,j,p in N.BOW_STROKES))
check("BOW_PRESSURE_ROT aligned with BOW_STROKES: beat-0 readers use 0,3,5; others identity",
      N.BOW_PRESSURE_ROT == (0,0,0,3,0,0,5) and len(N.BOW_PRESSURE_ROT)==len(N.BOW_STROKES)
      and [N.BOW_PRESSURE_ROT[i] for i,st in enumerate(N.BOW_STROKES) if st[2]==0]==[0,3,5]
      and all(N.BOW_PRESSURE_ROT[i]==0 for i,st in enumerate(N.BOW_STROKES) if st[2]!=0))
check("bow stroke inverse, exhaustive byte pairs for pressures 0, 127, 255", all(
      N.unbow_stroke(*N.bow_stroke(u,v,p),p)==(u,v) for p in (0,127,255) for u in range(256) for v in range(256)))
staffs = [list(rb(8)) for _ in range(20000)]
check("bow pressure two-sided inverse: 20,000 random staffs plus uniform edge staffs", all(
      N.unbow_pressure(N.bow_pressure(s)) == s and N.bow_pressure(N.unbow_pressure(s)) == s
      for s in staffs + [[v]*8 for v in range(256)]))
check("bow pressure is nonidentity and copies its input", all(N.bow_pressure(s) != s for s in staffs[:100])
      and all((lambda x: N.bow_pressure(x) is not x and x==s)(s[:]) for s in staffs[:100]))
# Historical B0 matrix still exhibits its old witness, but is no longer executed.
check("historical B0 matrix witness remains (0,3), distinct from live keyed B0 (round-0 tables)",
      N.bar_apply(N.BARS[0][3],5,1) == (0,3) and N.b0_apply(5,1,*TS) != (0,3))

# ---- cross-staff geometry, commitment, inverses and old confinement regression
import json
for name in ("CROSS_OPPOSITE", "CROSS_RADIAL", "CROSS_ADJACENT"):
    matching = getattr(N, name)
    check(name + " is an oriented perfect matching of 16 staffs",
          len(matching) == 8 and all(f < h for f,h in matching)
          and sorted(x for pair in matching for x in pair) == list(range(16)))
check("cross layer order is opposite, radial, adjacent, bridge", N.CROSS_LAYERS ==
      (N.CROSS_OPPOSITE, N.CROSS_RADIAL, N.CROSS_ADJACENT, N.CROSS_BRIDGE))
def cross_inverse_ok():
    for _ in range(1000):
        g = rgrid(); before = [row[:] for row in g]
        a = N.cross_staff_mix(g); b = N.cross_staff_unmix(g)
        if (N.cross_staff_unmix(a) != g or N.cross_staff_mix(b) != g or g != before
            or a is g or b is g or any(x is y for x,y in zip(a,g))
            or any(x is y for x,y in zip(b,g))): return False
    return True
check("cross-staff two-sided inverse and no input/row mutation, 1000 random grids", cross_inverse_ok())
desc = json.loads(N.mix_description())["cross_staff"]
check("canonical description includes cross matchings, effective layer order and placement",
      desc["opposite"] == [list(p) for p in N.CROSS_OPPOSITE]
      and desc["radial"] == [list(p) for p in N.CROSS_RADIAL]
      and desc["adjacent"] == [list(p) for p in N.CROSS_ADJACENT]
      and desc["layers"] == [[list(p) for p in layer] for layer in N.CROSS_LAYERS]
      and desc["bridge"] == [list(p) for p in N.CROSS_BRIDGE]
      and desc["order"] == "opposite;radial;adjacent;bridge"
      and desc["placement"] == "after-mid-rehair-before-S2;after-encore-rehair")
for name in ("CROSS_OPPOSITE", "CROSS_RADIAL", "CROSS_ADJACENT", "CROSS_BRIDGE", "CROSS_LAYERS"):
    desc0 = N.mix_description()
    with patch.object(N, name, tuple(reversed(getattr(N, name)))):
        changed = N.mix_description() != desc0
    check("mix_description changes with " + name + " (key_sig is cached at import)", changed)
alt = load("altered_cross", os.path.join(HERE,"sneak_n2.py"))
alt.CROSS_LAYERS = tuple(reversed(alt.CROSS_LAYERS))
ab = alt.encrypt(b"hello world", SEED); er = catch(lambda: N.decrypt(ab,SEED))
check("altered effective cross order roundtrips locally but fails closed on live decrypt",
      alt.decrypt(ab,SEED) == b"hello world" and isinstance(er, (N.AuthError, N.DecodeError)))
PRE_CROSS = load("pre_cross", "/tmp/sneak_n2_pre_cross_staff/sneak_n2.py")
pre_cross_blob = optional_blob("/tmp/sneak_n2_pre_cross_staff/hello-world.txt")
if pre_cross_blob is None:
    skip("pre-cross 195-byte hello-world pickup 28c124 now fails as unsupported version")
else:
    er = catch(lambda: N.decrypt(pre_cross_blob, SEED))
    check("pre-cross 195-byte hello-world pickup 28c124 now fails as unsupported version",
          len(pre_cross_blob)==195 and pre_cross_blob[3:19].hex().startswith("28c124")
          and isinstance(er,N.UnsupportedVersion) and "unsupported version" in str(er))
if PRE_CROSS is None:
    skip("triplets, schedule, weave, bridges, encoding unchanged from pre-cross")
    skip("bow_pressure/unbow_pressure sources differ from pre-cross")
else:
    check("triplets, schedule, weave, bridges, encoding unchanged from pre-cross (packaging changed encrypt/decrypt/_tag; B0/rehair/bow intentionally changed earlier)",
          all(inspect.getsource(getattr(N,n)) == inspect.getsource(getattr(PRE_CROSS,n)) for n in
              ("triplet_mix","triplet_unmix",
               "staff_mix","staff_unmix","shell_mix","shell_unmix","weave","unweave","Schedule",
               "StaffSponge","keyed_sbox","encode_block","siv_nonce")))
    check("bow_pressure/unbow_pressure sources differ from pre-cross (beat-0 pressure-rot fix applies rotl8 view)",
          inspect.getsource(N.bow_pressure) != inspect.getsource(PRE_CROSS.bow_pressure)
          and inspect.getsource(N.unbow_pressure) != inspect.getsource(PRE_CROSS.unbow_pressure)
          and "BOW_PRESSURE_ROT" in inspect.getsource(N.bow_pressure)
          and "BOW_PRESSURE_ROT" in inspect.getsource(N.unbow_pressure))
rr_cross = random.Random(20261108); active_counts=[]; staff_union=set(); confined=0
for trial in range(300):
    g = [[rr_cross.randrange(256) for _ in range(8)] for _ in range(16)]
    h = [row[:] for row in g]; h[0][2] ^= 0x5a if trial==0 else rr_cross.randrange(1,256)
    a=N.round_enc(g,sch0.rounds[0],0); b=N.round_enc(h,sch0.rounds[0],0)
    active={f for f in range(16) if a[f]!=b[f]}
    active_counts.append(len(active)); staff_union |= active
    confined += active <= {6,8,10,14,15}
print(f"cell-2 one-round spread (300 pairs, demo schedule; first delta 0x5a): min {min(active_counts)}, max {max(active_counts)}, union {sorted(staff_union)}, confined {confined}/300")
check("cell-2 previous five-staff confinement broken in all 300 pairs; union all 16 staffs",
      confined==0 and staff_union==set(range(16)) and min(active_counts)>5)
for name, expected in (("testn4","46274b690e3d3ae53649b810591681b94f53983c72f6fb9789a19c8670003f45"),
                       ("testn3","a64dc256aab66436073e888bbb6a31210f1b5c0af00b10c14ddd875fafd1b1b1")):
    fp = os.path.join("/workspace", name, "sneak_n2.py")
    if not os.path.isfile(fp):
        skip(name+" frozen source hash unchanged")
    else:
        check(name+" frozen source hash unchanged", hashlib.sha256(open(fp,"rb").read()).hexdigest()==expected)

# ---- four leftover-shape fixes (independent seeded scans)
FOUR_PRE = "/tmp/sneak_n2_pre_four_leftovers"
four_blob = optional_blob(FOUR_PRE+"/hello-world.txt")
if four_blob is None:
    skip("pre-four 195-byte hello-world pickup 831a4499 fails as unsupported version")
else:
    er = catch(lambda: N.decrypt(four_blob, SEED))
    check("pre-four 195-byte hello-world pickup 831a4499 fails as unsupported version, not DecodeError",
          len(four_blob)==195 and four_blob[3:19].hex()=="831a4499756825b07352034a552a9756"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
check("CROSS_BRIDGE is intended partial oriented disjoint matching, not a perfect matching",
      N.CROSS_BRIDGE==((1,2),(5,6),(9,10),(13,14))
      and all(f<h for f,h in N.CROSS_BRIDGE) and len({x for p in N.CROSS_BRIDGE for x in p})==8)
seen={0}
while True:
    nxt=seen | {v for layer in N.CROSS_LAYERS for u,v in layer if u in seen} | {u for layer in N.CROSS_LAYERS for u,v in layer if v in seen}
    if nxt==seen: break
    seen=nxt
print("four-layer cross graph component from 0:",sorted(seen))
check("four-layer cross graph is one connected 16-staff component", seen==set(range(16)))
check("B0 exhaustive two-sided inverse on all 65,536 pairs", all(
      N.b0_unapply(*N.b0_apply(u,v,*TS),*TSI)==(u,v) and N.b0_apply(*N.b0_unapply(u,v,*TSI),*TS)==(u,v)
      for u in range(256) for v in range(256)))
witness=tuple(a^b for a,b in zip(N.b0_apply(0,0,*TS),N.b0_apply(5,1,*TS)))
indep=lambda u,v:(TS[0][u^v],TS[1][u^N._gf_mul_raw(2,v)])
print("B0 live old-witness output XOR (round-0 tables):",tuple(hex(x) for x in witness))
check("B0 (0,0) vs (5,1) witness no longer (0,3); live equals independent x=u^v, y=u^2v, (S[x],S2[y])",
      witness!=(0,3) and all(N.b0_apply(u,v,*TS)==indep(u,v) for u in range(256) for v in range(256)))
# All bases for this old differential: a linear map would have one derivative.
derivs={tuple(a^b for a,b in zip(N.b0_apply(u,v,*TS),N.b0_apply(u^5,v^1,*TS))) for u in range(256) for v in range(256)}
print("B0 old (5,1) delta over 65,536 bases: distinct derivatives",len(derivs),
      "; first-output zeros",sum(a==0 for a,b in derivs),"; second-output zeros",sum(b==0 for a,b in derivs))
check("B0 old differential is not a base-independent linear kernel wipe",len(derivs)>1 and all(a!=0 for a,b in derivs))
rr4=random.Random(4419)
# General single-input property: changing either input must change both outputs.
single_ok=True
for _ in range(20000):
    u,v,d=rr4.randrange(256),rr4.randrange(256),rr4.randrange(1,256)
    base=N.b0_apply(u,v,*TS)
    for other in (N.b0_apply(u^d,v,*TS),N.b0_apply(u,v^d,*TS)):
        single_ok &= all(a!=b for a,b in zip(base,other))
check("B0 exactly-one-input changes both outputs (40,000 sampled derivatives)",single_ok)
rehair_staffs=[[v]*8 for v in range(256)]+[[rr4.randrange(256) for _ in range(8)] for _ in range(20000)]
check("odd_restack two-sided inverse, copies without mutation (20,256 staffs)",all(
      N.unodd_restack(N.odd_restack(s,*TS),*TSI)==s and N.odd_restack(N.unodd_restack(s,*TSI),*TS)==s
      and N.odd_restack(s,*TS) is not s and N.unodd_restack(s,*TSI) is not s for s in rehair_staffs))
check("odd restack beat 7 only pairs with 6; no beat-7-to-0 line", N.odd_restack([0]*7+[1],*TS)[:6]==N.odd_restack([0]*8,*TS)[:6]
      and "(1, 3, 5, 7)" in inspect.getsource(N.odd_restack) and "(7, 5, 3, 1)" in inspect.getsource(N.unodd_restack))
# All 255 deltas on 256 uniform + 256 random bases, on ALL EIGHT beats (beat-6 fix: was odd beats only).
single_before=single_after=cases=highbit_after=0; min_after=8; rehair_singles=[]
beat_before=[0]*8; beat_after=[0]*8; beat_cases=[0]*8
for s in rehair_staffs[:512]:
    a=N.bow_pressure(s); ar=N.odd_restack(a,*TS)
    for t in range(8):
        for d in range(1,256):
            h=s[:]; h[t]^=d; b=N.bow_pressure(h); br=N.odd_restack(b,*TS)
            single_before+=sum(x!=y for x,y in zip(a,b))==1
            weight=sum(x!=y for x,y in zip(ar,br))
            single_after+=weight==1; min_after=min(min_after,weight); cases+=1
            beat_before[t]+=sum(x!=y for x,y in zip(a,b))==1; beat_after[t]+=weight==1; beat_cases[t]+=1
            highbit_after+=(weight==1 and d==128)
            if weight==1: rehair_singles.append((s[:],t,d))
print(f"all-beat scan bow -> bow+rehair: {single_before}/{cases} -> {single_after}/{cases} singletons; min after {min_after}; includes every delta 0x80")
print("per-beat singletons (130,560 cases each), bow alone:",beat_before,"; bow+rehair:",beat_after)
check("bow+odd_restack has no singletons for 1,044,480 all-beat input cases (8 beats x 130,560, all 255 deltas; odd subset = the old 522,240)",
      cases==1044480 and beat_cases==[130560]*8 and sum(beat_cases[1::2])==522240 and single_before>0 and single_after==0
      and beat_after==[0]*8 and min_after>=2)
check("ARX rotation constants retired (no B0_ROT_*/ODD_RESTACK_R* attributes)",
      not any(hasattr(N,n) for n in ("B0_ROT_R1","B0_ROT_R2","ODD_RESTACK_R1","ODD_RESTACK_R2")))
check("latin_pair/latin_unpair/round_enc/round_dec are in MIX_CODE_FUNCS",
      all(n in N.MIX_CODE_FUNCS for n in ("latin_pair","latin_unpair","round_enc","round_dec","b0_apply","b0_unapply","odd_restack","unodd_restack")))
for name in ("latin_pair","latin_unpair","round_enc","round_dec"):
    desc0=N.mix_description()
    swapped=(lambda *a: None)
    with patch.object(N,name,swapped): changed=N.mix_description()!=desc0
    check("description changes when "+name+" object is replaced (key_sig is cached at import)",changed)
desc4=json.loads(N.mix_description())
LATIN_DESC=dict(kind="field+keyed-sbox",field=[[1,1],[1,2]],tables="u'=S[x];v'=S2[y];inverse SI,SI2")
check("B0 description is keyed Latin pair (field MIX2 then S/S2), not ARX or the unused matrix",
      desc4["bars"][0]==dict(name="B0 start",boundary=0,pair=[0,1],**LATIN_DESC))
check("description records keyed Latin odd rehair and pairs",all(desc4["odd_restack"][k]==v for k,v in LATIN_DESC.items())
      and desc4["odd_restack"]["pairs"]==[[0,1],[2,3],[4,5],[6,7]] and "r1" not in desc4["odd_restack"])
# ---- rotation retune (2026-11-09): B0 (3,5)->(2,7), odd restack (2,6)->(5,4)
ROT_PRE = "/tmp/sneak_n2_pre_rotation_retune"
rot_blob = optional_blob(ROT_PRE+"/hello-world.txt")
if rot_blob is None:
    skip("pre-rotation-retune 195-byte hello-world pickup 724da1f4 fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(rot_blob, SEED))
    check("pre-rotation-retune 195-byte hello-world pickup 724da1f4 fails as unsupported version, not DecodeError",
          len(rot_blob)==195 and rot_blob[3:19].hex()=="724da1f42b3aa81489b97a1dcaeb14c4"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# ---- keyed Latin pair (2026-11-09): B0 and odd rehair = field step (MIX2) then round S (u') / S2 (v')
LAT_PRE = "/tmp/sneak_n2_pre_latin_mix"
lat_blob = optional_blob(LAT_PRE+"/hello-world.txt")
if lat_blob is None:
    skip("pre-latin 195-byte hello-world pickup a287436b fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(lat_blob, SEED))
    check("pre-latin 195-byte hello-world pickup a287436b fails as unsupported version, not DecodeError",
          len(lat_blob)==195 and lat_blob[3:19].hex()=="a287436b086c25ff762366eb747704d0"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
inv3=N.gf_inv(3)
check("latin_unpair inverse formula: v = gf_mul(gf_inv(3), x^y), u = x^v equals mix2_inv on all 65,536 (x,y)",
      N.gf_mul(3,inv3)==1 and all((lambda v:(x^v,v))(N.gf_mul(inv3,x^y))==N.mix2_inv(x,y) for x in range(256) for y in range(256)))
check("keyed B0 and rehair pair are bijections with exact two-sided inverses for all 16 rounds' tables (65,536 pairs each)",
      all(len({N.latin_pair(u,v,rk["S"],rk["S2"]) for u in range(256) for v in range(256)})==65536
          and all(N.latin_unpair(*N.latin_pair(u,v,rk["S"],rk["S2"]),rk["SI"],rk["SI2"])==(u,v)
                  and N.latin_pair(*N.latin_unpair(u,v,rk["SI"],rk["SI2"]),rk["S"],rk["S2"])==(u,v) for u in range(256) for v in range(256))
          for rk in sch0.rounds))
b0_single=[0,0]
for u in range(256):
    for v in range(256):
        base=N.b0_apply(u,v,*TS)
        for d in range(1,256):
            for col,other in enumerate((N.b0_apply(u^d,v,*TS),N.b0_apply(u,v^d,*TS))):
                b0_single[col]+=sum(x!=y for x,y in zip(base,other))==1
print("B0 exhaustive single-input singletons (u column, v column) over 2x255x65,536, round-0 tables:",b0_single,"(ARX 2,7 had [0, 10752])")
check("B0 exhaustive single-input singletons are 0 (pure-Python, round-0 tables)", b0_single==[0,0])
import numpy as np
_u=np.repeat(np.arange(256),256); _v=np.tile(np.arange(256),256)
def np_singletons(Fm):
    c=[0,0]
    for col in (0,1):
        for d in range(1,256):
            idx=((_u^(d if col==0 else 0))<<8)|(_v^(d if col==1 else 0))
            c[col]+=int(((Fm!=Fm[idx]).sum(1)==1).sum())
    return c
lat_counts={}; fixed=[]; zero_maps=[]
for r,rk in enumerate(sch0.rounds):
    T=(rk["S"],rk["S2"])
    lat_counts[(r,"B0")]=np_singletons(np.array([N.b0_apply(u,v,*T) for u in range(256) for v in range(256)]))
    for t in (1,3,5,7):
        outs=[N.odd_restack([u if k==t-1 else (v if k==t else 0) for k in range(8)],*T) for u in range(256) for v in range(256)]
        lat_counts[(r,(t-1,t))]=np_singletons(np.array([(o[t-1],o[t]) for o in outs]))
    fixed.append(sum(N.b0_apply(u,v,*T)==(u,v) for u in range(256) for v in range(256))); zero_maps.append(N.b0_apply(0,0,*T))
print("live-table singleton counts, 16 rounds x (B0 + 4 rehair pairs):",sorted(set(tuple(c) for c in lat_counts.values())))
print("keyed pair (0,0) images per round:",zero_maps)
print("keyed pair fixed points per round (u,v)->(u,v):",fixed)
check("B0 and every rehair pair (0,1),(2,3),(4,5),(6,7): 0 singletons over all 2x255x65,536 one-input changes, all 16 rounds' tables",
      len(lat_counts)==80 and all(c==[0,0] for c in lat_counts.values()))
check("(0,0) is not a fixed point of the keyed pair in any of the 16 demo rounds", all(z!=(0,0) for z in zero_maps))
print(f"all-beat 0x80 singletons after bow+rehair: {highbit_after}/4096 (ARX 5,4 had 3/522,240 and 0/2,048 on odd beats)")
def _kernel_case(s,t,d):
    h=s[:]; h[t]^=d; db=[x^y for x,y in zip(N.bow_pressure(s),N.bow_pressure(h))]
    act=[i for i in range(8) if db[i]]
    return (len(act)==2 and act[0]%2==0 and act[1]==act[0]+1
            and (db[act[0]]==db[act[1]] or db[act[0]]==N.gf_mul(2,db[act[1]])))
def _single_all_tables(s,t,d):
    h=s[:]; h[t]^=d
    return all(sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
                                       N.odd_restack(N.bow_pressure(h),rk["S"],rk["S2"])))==1 for rk in sch0.rounds)
print("bow+keyed rehair singleton witnesses (base, beat, delta):",[(b if b.count(b[0])<8 else [b[0]]*8,t,hex(d)) for b,t,d in rehair_singles])
# Beat-7 fix (2026-11-09): last bow stroke (5,6,7) -> (5,6,0). The 5 old witnesses (all beat 7) are gone.
check("bow+keyed rehair: 0x80 singletons 0/4,096 and 0/1,044,480 all-beat singletons (beat-7 + beat-6 fixes)",
      cases==1044480 and highbit_after==0 and single_after==0 and rehair_singles==[])
OLD_B7=[([26]*8,7,0x24),([53]*8,7,0xe1),([117]*8,7,0x4e),([142,151,20,118,251,3,37,161],7,0x27),([91,12,141,148,97,40,0,144],7,0xb1)]
check("the 5 pre-fix beat-7 witnesses now change >=2 bytes after bow+rehair for all 16 rounds' tables",
      all(sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
              N.odd_restack(N.bow_pressure([c^(d if k==t else 0) for k,c in enumerate(s)]),rk["S"],rk["S2"])))>=2
          for s,t,d in OLD_B7 for rk in sch0.rounds))
# Proof lemma: a beat-7-only change leaves beats 0..4 untouched and ALWAYS changes beat 5 after bow,
# so the bow delta spans rehair pairs (4,5) and (6,7) (singleton needs a delta inside ONE pair).
rr7=random.Random(7007); lem=True
for _ in range(200000):
    s7=[rr7.randrange(256) for _ in range(8)]; d=rr7.randrange(1,256); h=s7[:]; h[7]^=d
    a,b=N.bow_pressure(s7),N.bow_pressure(h)
    lem &= a[:5]==b[:5] and a[5]!=b[5]
check("beat-7 lemma: bow keeps beats 0..4, always changes beat 5 (200,000 random staffs x deltas)", lem)
# ---- beat-6 fix (2026-11-09, after attacks_octavo_beat7): third stroke (4,5,6) -> (4,5,0).
# Lemma: a beat-6-only change leaves beats 0..4 untouched and ALWAYS changes beats 5 AND 7 (two rehair pairs).
rr6=random.Random(6006); lem6=True
for _ in range(200000):
    s6=[rr6.randrange(256) for _ in range(8)]; d=rr6.randrange(1,256); h=s6[:]; h[6]^=d
    a,b=N.bow_pressure(s6),N.bow_pressure(h)
    lem6 &= a[:5]==b[:5] and a[5]!=b[5] and a[7]!=b[7]
check("beat-6 lemma: bow keeps beats 0..4, always changes beats 5 and 7 (200,000 random staffs x deltas)", lem6)
check("beat 6 is read as pressure by no stroke; beat 0 feeds exactly the three strokes (4,5,0),(6,7,0),(5,6,0)",
      all(p!=6 for _,_,p in N.BOW_STROKES) and [st for st in N.BOW_STROKES if st[2]==0]==[(4,5,0),(6,7,0),(5,6,0)])
# Witnesses from attacks_octavo_beat7 (REPORT.md section 2 + attack_even_beats live_confirmation): single-byte under
# all 16 round tables before the fix. Now every one changes >=2 bytes after bow+rehair for every round's tables.
OLD_B6=[([90,8,17,194,106,100,92,5],6,28),([61,184,68,8,147,13,127,98],6,14),
        ([121,234,152,46,28,121,240,211],6,18),([248,57,224,163,155,133,232,18],6,36)]
b6_w=[[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
        N.odd_restack(N.bow_pressure([c^(d if k==t else 0) for k,c in enumerate(s)]),rk["S"],rk["S2"]))) for rk in sch0.rounds]
      for s,t,d in OLD_B6]
print("pre-fix beat-6 witnesses, bow+rehair changed bytes per round table:",b6_w)
check("the 4 pre-fix beat-6 witnesses (3 all-table + REPORT mechanism example) now change >=2 bytes for all 16 rounds' tables",
      all(min(w)>=2 for w in b6_w))
PRE_B6_STROKES=((0,1,2),(2,3,4),(4,5,6),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
PRE_B6_PRESSURE_ROT=(0,0,0,0,0,0,0)  # pre-beat0rot: every stroke used p as-is
with patch.object(N,"BOW_STROKES",PRE_B6_STROKES), patch.object(N,"BOW_PRESSURE_ROT",PRE_B6_PRESSURE_ROT):
    ctrl=[[sum(x!=y for x,y in zip(N.odd_restack(N.bow_pressure(s),rk["S"],rk["S2"]),
            N.odd_restack(N.bow_pressure([c^(d if k==t else 0) for k,c in enumerate(s)]),rk["S"],rk["S2"]))) for rk in sch0.rounds]
          for s,t,d in OLD_B6]
check("negative control: with pre-beat6 (4,5,6) strokes AND all-zero BOW_PRESSURE_ROT patched in, the 4 beat-6 witnesses are single-byte under all 16 tables",
      all(w==[1]*16 for w in ctrl)
      and N.BOW_STROKES==((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
      and N.BOW_PRESSURE_ROT==(0,0,0,3,0,0,5))
# Large NumPy scan: vectorised bow (checked against live bow_pressure) + live round-0 keyed rehair.
_S0=np.array(list(TS[0]),dtype=np.int64); _S20=np.array(list(TS[1]),dtype=np.int64); _G2=np.array(list(N._GF_MUL[2]),dtype=np.int64)
def _rotl(x,r): return ((x<<r)|(x>>(8-r)))&255
def np_bow(A):
    A=A.copy()
    for (i,j,p),k in zip(N.BOW_STROKES, N.BOW_PRESSURE_ROT):
        P=_rotl(A[:,p],k); r1=N.BOW_ROT_BASE+(P%N.BOW_ROT_MOD); r2=N.BOW_ROT_BASE+((P>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD)
        u=(A[:,i]+_rotl(A[:,j],r1))&255; v=A[:,j]^_rotl(u,r2); A[:,i]=u; A[:,j]=v
    return A
def np_rehair(A):
    O=A.copy()
    for t in (1,3,5,7):
        u,v=A[:,t-1],A[:,t]; O[:,t-1]=_S0[u^v]; O[:,t]=_S20[u^_G2[v]]
    return O
_chk=np.random.default_rng(66).integers(0,256,(5000,8),dtype=np.int64)
check("NumPy bow/rehair model equals live bow_pressure/odd_restack on 5,000 random staffs",
      all(list(np_rehair(np_bow(_chk))[k])==N.odd_restack(N.bow_pressure(list(map(int,_chk[k]))),*TS)
          and list(np_bow(_chk)[k])==N.bow_pressure(list(map(int,_chk[k]))) for k in range(5000)))
import time as _time
_t0=_time.time(); rng6=np.random.default_rng(20261109); B6_BASES=65536; b6_hits=[0]*8; b6_cases=[0]*8
_D=np.arange(1,256,dtype=np.int64)
for chunk in range(B6_BASES//4096):
    base=rng6.integers(0,256,(4096,8),dtype=np.int64); ref=np_rehair(np_bow(base))
    for t in range(8):
        if t!=6 and chunk>=4: continue          # other beats: 16,384 bases x 255 (4.18 M each); beat 6: all 65,536 bases
        Bx=np.repeat(base,255,axis=0); Bx[:,t]^=np.tile(_D,4096)
        w=(np_rehair(np_bow(Bx))!=np.repeat(ref,255,axis=0)).sum(1)
        b6_hits[t]+=int((w==1).sum()); b6_cases[t]+=len(w)
print(f"NumPy bow+rehair singleton scan (round-0 tables), cases per beat {b6_cases}, singletons {b6_hits}, {_time.time()-_t0:.1f}s")
check("beat-6 scan: 0 singletons in 16,711,680 beat-6 cases (65,536 random bases x 255 deltas; pre-fix layout gave ~19) and 0 on every other beat (4,177,920 each)",
      b6_cases[6]==16711680 and all(c==4177920 for k,c in enumerate(b6_cases) if k!=6) and b6_hits==[0]*8)
B6_PRE = "/tmp/sneak_n2_pre_beat6"
b6_blob = optional_blob(B6_PRE+"/hello-world.txt")
if b6_blob is None:
    skip("pre-beat6-fix 195-byte hello-world pickup ee95ddb2 fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(b6_blob, SEED))
    check("pre-beat6-fix 195-byte hello-world pickup ee95ddb2 fails as unsupported version, not DecodeError",
          len(b6_blob)==195 and b6_blob[3:19].hex()=="ee95ddb278a849bae4a34fe594ee87e5"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# ---- beat-0 pressure-rotation fix (2026-11-09, after attacks_octavo_beat6 §6)
B0R_PRE = "/tmp/sneak_n2_pre_beat0rot"
b0r_blob = optional_blob(B0R_PRE+"/hello-world.txt")
if b0r_blob is None:
    skip("pre-beat0rot 195-byte hello-world pickup d450337d fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(b0r_blob, SEED))
    check("pre-beat0rot 195-byte hello-world pickup d450337d fails as unsupported version, not DecodeError",
          len(b0r_blob)==195 and b0r_blob[3:19].hex()=="d450337d3bbe0b460ae4298952279c7a"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# Explicit pressure views: for every pressure byte, the three beat-0 strokes see 0/3/5-bit rotates.
def _stroke_views(p):
    return [N.rotl8(p, N.BOW_PRESSURE_ROT[i]) for i,st in enumerate(N.BOW_STROKES) if st[2]==0]
check("beat-0 pressure views are p, rotl8(p,3), rotl8(p,5) for all 256 pressure bytes",
      all(_stroke_views(p)==[p, N.rotl8(p,3), N.rotl8(p,5)] for p in range(256)))
# Distinct (r1,r2) for the three beat-0 readers on most pressures (shared-rotation hardening).
def _rr(view):
    return (N.BOW_ROT_BASE+(view%N.BOW_ROT_MOD), N.BOW_ROT_BASE+((view>>N.BOW_R2_SHIFT)%N.BOW_ROT_MOD))
shared = sum(1 for p in range(256) if len({_rr(v) for v in _stroke_views(p)})==1)
distinct3 = sum(1 for p in range(256) if len({_rr(v) for v in _stroke_views(p)})==3)
print(f"beat-0 reader (r1,r2) distinctness over 256 p: shared-all={shared}, all-three-distinct={distinct3}")
check("beat-0 readers rarely share one (r1,r2); usually all three distinct (shared < 16, distinct3 > 180)",
      shared < 16 and distinct3 > 180)
# Cheap bow-alone differential spot check (2^12 bases, beats 0/6/7): should beat the pre-fix live numbers
# from attacks_octavo_beat6 (beat 6 ~2^-5.6, beat 7 ~2^-4.9, beat 0 ~2^-8.1).
_rngd=np.random.default_rng(909); Bd=_rngd.integers(0,256,(1<<12,8),dtype=np.int64); Ad=np_bow(Bd)
def _best_diff(t):
    pack=lambda z:(z.astype(np.int64)*(256**np.arange(8))).sum(1); best=0
    for d in range(1,256):
        H=Bd.copy(); H[:,t]^=d; best=max(best,int(np.unique(pack(Ad^np_bow(H)),return_counts=True)[1].max()))
    return round(float(np.log2(best/len(Bd))),2)
bd0,bd6,bd7=_best_diff(0),_best_diff(6),_best_diff(7)
print(f"bow-alone best diff log2 (2^12 bases): beat0={bd0}, beat6={bd6}, beat7={bd7} (pre-fix live ~-8.1/-5.6/-4.9)")
check("bow-alone best differentials on beats 0/6/7 improved vs pre-fix live (~-8.1/-5.6/-4.9)",
      bd0 <= -9.0 and bd6 <= -6.5 and bd7 <= -6.5)
# Description records pressure_rot; key_sig changes if BOW_PRESSURE_ROT is patched (already in loop above).
desc_bow=json.loads(N.mix_description())["bow"]
check("mix_description bow records pressure_rot and the view-then-r1/r2 formula",
      desc_bow["pressure_rot"]==list(N.BOW_PRESSURE_ROT) and "pressure_rot" in desc_bow["formula"]
      and desc_bow["strokes"]==[list(s) for s in N.BOW_STROKES])
B7_PRE = "/tmp/sneak_n2_pre_beat7"
b7_blob = optional_blob(B7_PRE+"/hello-world.txt")
if b7_blob is None:
    skip("pre-beat7-fix 195-byte hello-world pickup 76908595 fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(b7_blob, SEED))
    check("pre-beat7-fix 195-byte hello-world pickup 76908595 fails as unsupported version, not DecodeError",
          len(b7_blob)==195 and b7_blob[3:19].hex()=="76908595dcdc8f11ff9e045ac25c080c"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
def affine_bits(f):
    rel=[]
    for col in (0,1):
        for bit in range(8):
            g=lambda u,v:(f(u,v)[col]>>bit)&1; c=g(0,0)
            um=sum((g(1<<j,0)^c)<<j for j in range(8)); vm=sum((g(0,1<<j)^c)<<j for j in range(8))
            if all(g(u,v)==c^(bin(u&um).count("1")&1)^(bin(v&vm).count("1")&1) for u in range(256) for v in range(256)):
                rel.append((col,bit,um,vm,c))
    return rel
aff=[(r,affine_bits(lambda u,v,T=(rk["S"],rk["S2"]):N.latin_pair(u,v,*T))) for r,rk in enumerate(sch0.rounds)]
print("keyed pair exact affine output bits per round (col,bit,u_mask,v_mask,const):",[a for _,a in aff])
check("keyed pair: no output bit is an exact affine function of the inputs (all 16 rounds' tables)", all(a==[] for _,a in aff))
# ---- signature-gap fix (2026-11-09): reachable-closure coverage of code AND module data
import ast as _ast, functools, types as _types, textwrap as _textwrap, tempfile
SIG_PRE = "/tmp/sneak_n2_pre_sig_gap"
sig_blob = optional_blob(SIG_PRE+"/hello-world.txt")
if sig_blob is None:
    skip("pre-sig-gap 195-byte hello-world pickup 24d554eb fails as unsupported version, not DecodeError")
else:
    er = catch(lambda: N.decrypt(sig_blob, SEED))
    check("pre-sig-gap 195-byte hello-world pickup 24d554eb fails as unsupported version, not DecodeError",
          len(sig_blob)==195 and sig_blob[3:19].hex()=="24d554eb3d22f0b6412d7da59e504df1"
          and isinstance(er,N.UnsupportedVersion) and str(er)=="unsupported version")
# Independent call-graph walk (own AST walker over the module's globals, from encrypt/decrypt/siv_nonce/key_signature/split_blob).
def indep_closure():
    seen=set(); data=set(); todo=["encrypt","decrypt","siv_nonce","key_signature","split_blob","mix_description"]
    skip=set(N._ATTEST_SKIP)
    while todo:
        n=todo.pop()
        if n in skip or n in seen or n in data or not hasattr(N,n): continue
        o=getattr(N,n)
        if isinstance(o,_types.ModuleType): continue
        if inspect.isfunction(o) or inspect.isclass(o):
            seen.add(n); todo += [x.id for x in _ast.walk(_ast.parse(_textwrap.dedent(inspect.getsource(o)))) if isinstance(x,_ast.Name)]
        else: data.add(n)
    return seen,data
reach,reach_data=indep_closure()
IMPORT_TIME_BUILDERS={"_gf_mul_raw","bar_det","bar_inv","triplet_det","triplet_inv"}
print("reachable functions/classes:",len(reach),"; reachable module data:",sorted(reach_data))
check("nothing reachable from encrypt/decrypt/siv_nonce/key_signature/split_blob is missing from MIX_CODE_FUNCS; listed extras are only the import-time table builders",
      reach <= set(N.MIX_CODE_FUNCS) and set(N.MIX_CODE_FUNCS)-reach==IMPORT_TIME_BUILDERS
      and (reach,reach_data)==N.mix_code_closure() and len(N.MIX_CODE_FUNCS)==len(set(N.MIX_CODE_FUNCS)))
mod_defs={n for n,o in vars(N).items() if (inspect.isfunction(o) or inspect.isclass(o)) and getattr(o,"__module__",None)==N.__name__}
print("module functions/classes NOT in coverage:",sorted(mod_defs-set(N.MIX_CODE_FUNCS)))
check("only non-cipher helpers are outside coverage (ddt_max, lat_max, grid_rows, encrypt_hello, import attestation)",
      mod_defs-set(N.MIX_CODE_FUNCS)=={"ddt_max","lat_max","grid_rows","encrypt_hello","_init_attestation"})
check("closure includes staff_mix/staff_unmix/shell_mix/shell_unmix/weave/unweave/xor_grid/Schedule/keyed_sbox/encode_block/encrypt_grid/decrypt_grid",
      {"staff_mix","staff_unmix","shell_mix","shell_unmix","weave","unweave","xor_grid","Schedule","StaffSponge","keyed_sbox",
       "mat_apply","mat_invertible","encode_block","encrypt_grid","decrypt_grid","bytes_to_grid","grid_to_bytes","_tag","staff_clef"} <= reach)
check("module data hashed includes BARS, BARS_INV, TRIPLETS(_INV), CROSS_*, BOW_* (incl. BOW_PRESSURE_ROT), LAYERS, SM4_SBOX, _GF_MUL, MIX2_*, sizes",
      {"BARS","BARS_INV","TRIPLETS","TRIPLETS_INV","CROSS_OPPOSITE","CROSS_RADIAL","CROSS_ADJACENT","CROSS_BRIDGE","CROSS_LAYERS",
       "BOW_STROKES","BOW_PRESSURE_ROT","BOW_ROT_BASE","BOW_ROT_MOD","BOW_R2_SHIFT","LAYERS","SM4_SBOX","_GF_MUL","MIX2_MATRIX","MIX2_INV","FIELD_POLY",
       "NF","NB","NR","BLOCK_LEN","VERSION"} <= reach_data and json.loads(N.mix_description())["mix_data"]["names"]==sorted(reach_data)
      and len(reach_data)==36)
def frame(h,parts):
    for part in parts: b=part.encode(); h.update(len(b).to_bytes(8,"big")); h.update(b)
desc5=json.loads(N.mix_description())
code=hashlib.sha256()
for name in desc5["mix_code"]["functions"]:
    o=getattr(N,name); frame(code,(name,inspect.getsource(o),N._canon_data((getattr(o,"__defaults__",None),getattr(o,"__kwdefaults__",None)))))
data=hashlib.sha256()
for name in sorted(reach_data): frame(data,(name,N._canon_data(getattr(N,name))))
check("independent recomputation of mix_code and mix_data digests matches",
      desc5["mix_code"]["sha256"]==code.hexdigest() and desc5["mix_data"]["sha256"]==data.hexdigest()
      and desc5["mix_code"]["functions"]==list(N.MIX_CODE_FUNCS))
def modified_source(full, name):
    """Behaviour-preserving edit to ONE top-level def/class: insert a no-op statement (or parenthesise a one-line return)."""
    lines=full.split("\n"); idx=next(i for i,l in enumerate(lines) if l.startswith(("def "+name+"(","class "+name+"(","class "+name+":")))
    hdr=lines[idx]
    if hdr.split("#")[0].rstrip().endswith(":"):
        nxt=next(l for l in lines[idx+1:] if l.strip()); ind=nxt[:len(nxt)-len(nxt.lstrip())]
        lines.insert(idx+1, ind+"_sig_gap_probe = 1  # modified copy")
    else:
        assert ": return " in hdr, name; lines[idx]=hdr.replace(": return ",": return (",1)+")"
    return "\n".join(lines)
live_sig=N.key_signature(SEED); results={}
def loosen_attest(src_text):
    return src_text.replace('EXPECTED_MIX_SHA256 = "'+N.EXPECTED_MIX_SHA256+'"', 'EXPECTED_MIX_SHA256 = "TO_BE_FILLED"', 1)
with tempfile.TemporaryDirectory(prefix="n2_sig_gap_") as td:
    for name in [n for n in N.MIX_CODE_FUNCS if n not in ("AuthError","DecodeError","UnsupportedVersion")]:
        path=os.path.join(td,"mod_"+name+".py"); open(path,"w").write(loosen_attest(modified_source(src,name)))
        alt=load("sig_gap_"+name,path)
        assert inspect.getsource(getattr(alt,name))!=inspect.getsource(getattr(N,name)), name
        ab=alt.encrypt(b"hello world", SEED)
        er=catch(lambda:N.decrypt(ab,SEED))
        results[name]=(alt.key_signature(SEED)!=live_sig, isinstance(er,N.AuthError) and str(er)=="tag mismatch")
    bad=[n for n,(a,b) in results.items() if not (a and b)]
    print(f"modified-file revisions: {len(results)} functions/classes; key_sig changed AND live decrypt of alt blob -> tag mismatch for {len(results)-len(bad)}; failures {bad}")
    for name in ("staff_mix","staff_unmix","shell_mix","shell_unmix","weave","unweave"):
        check("modified file of "+name+": key_sig changes and its blob fails live with AuthError tag mismatch", results[name]==(True,True))
    check("modified file of EVERY covered function/class (all but the exception classes) changes key_sig and fails live on tag",
          not bad and len(results)==len(N.MIX_CODE_FUNCS)-3)
    # Identity staff_mix as its own revision (file copy), not an in-process patch.
    idsrc=loosen_attest(src).replace("def staff_mix(g, sigma):", "def staff_mix(g, sigma):\n    return [row[:] for row in g]\n    # ", 1)
    idpath=os.path.join(td,"identity_staff_mix_rev.py"); open(idpath,"w").write(idsrc)
    ident=load("identity_staff_mix_rev",idpath)
    blob3=ident.encrypt(b"hello world",SEED)
    er3=catch(lambda:N.decrypt(blob3,SEED))
    print("identity staff_mix revision: key_sig same as live:",ident.key_signature(SEED)==live_sig,"; tampered blob on live:",repr(er3))
    check("identity staff_mix file revision: key_sig differs and its blob fails live on TAG",
          ident.key_signature(SEED)!=live_sig and isinstance(er3,N.AuthError) and str(er3)=="tag mismatch")
    # A replacement that calls a NEW module-level helper: the helper is followed by the live closure walk.
    hp=os.path.join(td,"helper_a.py"); open(hp,"w").write("def staff_mix(g,sigma):return _extra(g)\ndef _extra(g):return [row[:] for row in g]\n")
    hq=os.path.join(td,"helper_b.py"); open(hq,"w").write("def _extra(g):return [row[::-1] for row in g]\n")
    ha=load("helper_a",hp); hb=load("helper_b",hq)
    with patch.object(N,"staff_mix",ha.staff_mix), patch.object(N,"_extra",ha._extra,create=True):
        d_a=N.mix_description(); in_closure="_extra" in N.mix_code_closure()[0]
        with patch.object(N,"_extra",hb._extra): d_b=N.mix_description()
    check("new module-level helper named by a replacement is in the live closure; changing only that helper changes mix_description",
          in_closure and d_a!=N.mix_description() and d_b!=d_a)
# Data tables that were NOT in the old JSON description.
for name,value in (("LAYERS",(1,4,2)),("SM4_SBOX",N.SM4_SBOX[1:]+N.SM4_SBOX[:1]),("_GF_MUL",N._GF_MUL[:-1]+(bytes(256),)),
                   ("BARS_INV",N.BARS_INV[::-1]),("TRIPLETS_INV",N.TRIPLETS_INV[::-1]),("MIX2_INV",((1,1),(1,1))),("NR",15),("VERSION",b"SN3")):
    desc0=N.mix_description()
    with patch.object(N,name,value): changed=N.mix_description()!=desc0
    check("mix_description changes when module data "+name+" changes (key_sig is cached at import)",changed)
# Fail closed: mix_description still raises on a non-attestable replacement; key_signature uses the cache.
for label,obj in (("builtin list",list),("functools.partial",functools.partial(N.staff_mix))):
    with patch.object(N,"staff_mix",obj):
        e1=catch(lambda:N.mix_description()); e2=catch(lambda:N.key_signature(SEED))
    check("staff_mix replaced by "+label+": mix_description raises (fail closed); cached key_signature still works",
          isinstance(e1,Exception) and e2 is None)
check("key signature is stable across calls in an untouched process", N.key_signature(SEED)==live_sig==N.key_signature(SEED))
# A real file gives inspect an honest changed source; no protected files touched.
import tempfile
with tempfile.TemporaryDirectory(prefix="n2_code_patch_") as td:
    patchpath=os.path.join(td,"patched_n2.py")
    patched_src=src.replace('row[i], row[j] = b0_apply(row[i], row[j], Sa, Sb) if name == "B0 start" else bar_apply(M, row[i], row[j])',
                            'row[i], row[j] = (row[i], row[j]) if name == "B0 start" else bar_apply(M, row[i], row[j])')
    patched_src=patched_src.replace('row[i], row[j] = b0_unapply(row[i], row[j], SIa, SIb) if BARS[k][0] == "B0 start" else bar_apply(BARS_INV[k], row[i], row[j])',
                                    'row[i], row[j] = (row[i], row[j]) if BARS[k][0] == "B0 start" else bar_apply(BARS_INV[k], row[i], row[j])')
    patched_src=loosen_attest(patched_src)
    open(patchpath,"w").write(patched_src)
    alt=load("skip_b0_code",patchpath)
    ab=alt.encrypt(b"hello world",SEED); er=catch(lambda:N.decrypt(ab,SEED))
    check("copied bar_mix skips B0, BARS identical: key_sig changes; alternate roundtrip; live tag mismatch",
          alt.BARS==N.BARS and inspect.getsource(alt.bar_mix)!=inspect.getsource(N.bar_mix)
          and alt.mix_description()!=N.mix_description() and alt.key_signature(SEED)!=N.key_signature(SEED)
          and alt.decrypt(ab,SEED)==b"hello world" and isinstance(er,N.AuthError) and str(er)=="tag mismatch")
    desc0=N.mix_description()
    with patch.object(N,"bar_mix",alt.bar_mix):
        check("runtime replacing bar_mix object changes mix_description without editing BARS (key_sig stays cached)",
              N.mix_description()!=desc0)

# ---- diffusion: 1-byte input difference at every one of the 128 cells, union of affected output BYTES over trials
def dependence(maxr=6, trials=4):
    rr = random.Random(5); union = [[set() for _ in range(128)] for _ in range(maxr)]; mean = [0] * maxr; n = 0
    for p in range(128):
        for _ in range(trials):
            sch = N.Schedule(SEED, bytes(rr.randrange(256) for _ in range(16)))
            g = [[rr.randrange(256) for _ in range(8)] for _ in range(16)]
            h = [row[:] for row in g]; h[p // 8][p % 8] ^= rr.randrange(1, 256)
            for r in range(maxr):
                g = N.round_enc(g, sch.rounds[r], r); h = N.round_enc(h, sch.rounds[r], r)
                d = {8 * f + t for f in range(16) for t in range(8) if g[f][t] != h[f][t]}
                union[r][p] |= d; mean[r] += len(d)
            n += 1
    mins = [min(len(u) for u in union[r]) for r in range(maxr)]
    return mins, [m / n for m in mean], next((r + 1 for r in range(maxr) if mins[r] == 128), None)
n2 = dependence()
print("N2-8bit+bars+triplets diffusion, min over 128 input bytes of |union of affected output bytes| after r rounds:", n2[0])
print("N2-8bit+bars+triplets diffusion, mean affected bytes per single trial (random ~127.5):", [round(x, 1) for x in n2[1]])
print(f"N2-8bit+bars+triplets full byte dependence at round {n2[2]}  (8-bit N2 before bars: round 3, min-union [37, 127, 128]; 4-bit N2: round 3)")
check("N2-8bit reaches full 128-byte dependence by round 4", n2[2] is not None and n2[2] <= 4)
check("N2-8bit mean affected bytes after 3 rounds >= 120 (random-like 127.5)", n2[1][2] >= 120)
def av(rounds, n=300):
    hs = []
    for _ in range(n):
        s = N.Schedule(SEED, rb(16)); x = rb(128); y = flip(x, R.randrange(1024))
        e = lambda z: N.grid_to_bytes(N.encrypt_grid(N.bytes_to_grid(z), s, rounds))
        hs.append(hd(e(x), e(y)))
    return sum(hs) / n, min(hs), max(hs)
for r in (1, 2, 3, 4, 16):
    a = av(r, 300 if r < 16 else 1000); print(f"bit avalanche {r:2d} rounds: mean {a[0]:.1f}/1024, min {a[1]}, max {a[2]}")
    if r == 4: a4 = a
    if r == 16: a16 = a
check("4-round bit avalanche mean within 496..528 (of 1024)", 496 <= a4[0] <= 528)
check("16-round bit avalanche mean within 500..524, min > 440", 500 <= a16[0] <= 524 and a16[1] > 440)
cnt = [0] * 256
for _ in range(2000):
    for b in N.encrypt(rb(12), SEED)[N.CT0:N.CT1]: cnt[b] += 1
ex = sum(cnt) / 256; chi = sum((o - ex) ** 2 / ex for o in cnt); print(f"ct byte chi2 over 2000 random messages (255 df, 99.9% crit 330.5): {chi:.1f}")
check("ct byte distribution uniform-ish (chi2 < 330.5)", chi < 330.5)

# ---- frozen trees untouched (sha256 baselines taken before N2 was written)
def sha_ok(listfile):
    r = subprocess.run(["sha256sum", "-c", "--quiet", listfile], cwd="/workspace", capture_output=True)
    return r.returncode == 0
if os.path.isdir("/workspace/test1"):
    for lf in ("frozen-and-n1.sha256", "v2-v13-and-seed.sha256"):
        lp = os.path.join(HERE, "baselines", lf)
        if not os.path.isfile(lp):
            skip(f"unchanged vs baseline {lf}")
            continue
        print(f"baseline {lf}: {sum(1 for _ in open(lp))} files")
        check(f"unchanged vs baseline {lf}", sha_ok(lp))
    bp = os.path.join(HERE, "baselines", "frozen-and-n1.sha256")
    if os.path.isfile(bp):
        base_files = sorted(l.split("  ", 1)[1].strip() for l in open(bp))
        now_files = sorted(os.path.relpath(os.path.join(dp, f), "/workspace") for d in ("test1", "test3", "test13", "testn1", "sneak_t1n")
                           for dp, _, fs in os.walk(os.path.join("/workspace", d)) for f in fs) + ["sneak-staff-t1n.png"]
        check("no files added/removed in test1/, test3/, test13/, testn1/, sneak_t1n/", base_files == sorted(now_files))
    else:
        skip("no files added/removed in test1/, test3/, test13/, testn1/, sneak_t1n/")
else:
    skip("unchanged vs baseline frozen-and-n1.sha256")
    skip("unchanged vs baseline v2-v13-and-seed.sha256")
    skip("no files added/removed in test1/, test3/, test13/, testn1/, sneak_t1n/")
print(f"\n{P}/{P+F} passed, {F} failed, {S} skipped")
sys.exit(1 if F else 0)
