"""Sneak staff-core N2 (8-bit cells) — homemade 1024-bit block cipher (descended from N1) + HMAC-SHA256 seal.

WARNING: homemade, unreviewed scheme. NOT for real secrets.
For anything that matters use AES-GCM-SIV (RFC 8452), age, or libsodium.

What is homemade: the whole 1024-bit block cipher (16 faces x 8 beats on dual octahedra, one BYTE per beat,
keyed SM4-affine 8-bit S-boxes, face-beat weave, staff butterflies on open (linear, unlooped) 8-beat staffs, seven
named pair mixes (keyed Latin B0, six field pairs) plus six overlapping triplet mixes per staff (four measures of 2/4) and shell bridges built from the two-cell SM4-field mix (u XOR v, u XOR (2 times v)), with nonlinear bow pressure, keyed Latin odd-beat rehair, and four matching-beat cross-staff layers after each bow). What is NOT homemade: SHA-256 is the one-way
"staff sponge" that expands seed+nonce into the schedule, HMAC-SHA256 is the integrity tag, and the base 8-bit
S-box table is the published SM4/SMS4 S-box (GB/T 32907-2016). No AES, AES S-box, MixColumns or GCM anywhere.
See SPEC.md.
"""
import hashlib, hmac, os, json, inspect, ast, textwrap, types

VERSION = b"SN2"
NF, NB, NR = 16, 8, 16            # faces, beats, rounds (16 rounds <-> 16 faces)
CELL_BITS = 8                     # one byte per beat (was a 4-bit nibble)
NONCE_LEN, BLOCK_LEN, TAG_LEN = 16, 128, 32
PICKUP_LEN = 16                   # random anacrusis before the downbeat (os.urandom, fresh per encrypt)
BLOB_LEN = len(VERSION) + PICKUP_LEN + NONCE_LEN + BLOCK_LEN + TAG_LEN    # 195
MAX_MSG = 127
PK0, N0 = 3, 3 + PICKUP_LEN                                    # pickup = blob[3:19], nonce = blob[19:35]
CT0, CT1 = N0 + NONCE_LEN, N0 + NONCE_LEN + BLOCK_LEN          # ct = blob[35:163], tag = blob[163:195]
SEED_PATH = "/workspace/sneak1024-seed.txt"

# SM4 (SMS4) 8-bit S-box, GB/T 32907-2016 Fig./Table "S-box", as printed in draft-ribose-cfrg-sm4-10 sec. 6.2.3
# (Tse, Wong, Saarinen, IRTF CFRG, 2018). Published DDT max 4/256 (2^-6), nonlinearity 112 (LAT max |bias| 16/256).
# Note (honest): like every GF(2^8)-inversion-based S-box, SM4's is affine-equivalent to the inversion map.
SM4_SBOX = bytes.fromhex(
    "d690e9fecce13db716b614c228fb2c05" "2b679a762abe04c3aa44132649860699" "9c4250f491ef987a33540b43edcfac62" "e4b31ca9c908e895"
    "80df94fa758f3fa6" "4707a7fcf37317ba83593c19e6854fa8" "686b81b27164da8bf8eb0f4b70569d35" "1e240e5e6358d1a2"
    "25227c3b01217887" "d40046579fd327524c3602e7a0c4c89e" "eabf8ad240c738b5a3f7f2cef96115a1" "e0ae5da49b341a55"
    "ad933230f58cb1e3" "1df6e22e8266ca60c02923ab0d534e6f" "d5db3745defd8e2f03ff6a726d6c5b51" "8d1baf92bbddbc7f"
    "11d95c411f105ad8" "0ac13188a5cd7bbd2d74d012b8e5b4b0" "8969974a0c96777e65b9f109c56ec684" "18f07dec3adc4d20"
    "79ee5f3ed7cb3948")
assert len(SM4_SBOX) == 256 and len(set(SM4_SBOX)) == 256

class AuthError(ValueError): """Tag mismatch / malformed blob. No payload is ever returned."""
class DecodeError(ValueError): """Tag was valid but the decrypted block is not a well-formed encoding."""

# ---------------------------------------------------------------- seed
def load_seed(path=SEED_PATH) -> bytes:
    """Same file and parsing as N1 (256 hex digits = 1024 bits), returned as 128 big-endian bytes."""
    h = "".join(c for c in open(path).read().lower() if c in "0123456789abcdef")
    if len(h) != 256: raise ValueError(f"seed must be 256 hex digits, got {len(h)}")
    return bytes.fromhex(h)

def _seed_bytes(seed) -> bytes:
    if seed is None: return load_seed()
    if isinstance(seed, int): return seed.to_bytes(128, "big")          # N1-style integer key
    seed = bytes(seed)
    if len(seed) != 128: raise ValueError("seed must be 128 bytes (1024 bits)")
    return seed

# ---------------------------------------------------------------- staff sponge (SHA-256 underneath)
class StaffSponge:
    """Squeezes SHA-256(b"SN2/" || domain || counter32 || seed || nonce) blocks, counter = 0,1,2,...
    Distinct one-byte domains separate the MAC key (b"M") from the round schedule (b"K").
    One-way: from squeezed output (round keys) + public nonce you cannot solve back for the seed
    without inverting SHA-256 (N1's schedule was a linear rotate/XOR map and was solved directly)."""
    def __init__(self, domain: bytes, seed: bytes, nonce: bytes):
        self.d, self.s, self.n, self.ctr, self.buf = domain, seed, nonce, 0, b""
    def _more(self):
        self.buf += hashlib.sha256(b"SN2/" + self.d + self.ctr.to_bytes(4, "big") + self.s + self.n).digest()
        self.ctr += 1
    def take(self, k: int) -> bytes:
        while len(self.buf) < k: self._more()
        out, self.buf = self.buf[:k], self.buf[k:]; return out
    def below(self, n: int) -> int:
        """Unbiased integer in [0, n) by rejection on single bytes (n <= 256)."""
        lim = 256 - 256 % n
        while True:
            b = self.take(1)[0]
            if b < lim: return b % n
    def perm(self, n: int):
        p = list(range(n))
        for i in range(n - 1, 0, -1):
            j = self.below(i + 1); p[i], p[j] = p[j], p[i]
        return p

# ---------------------------------------------------------------- GF(2)^8 affine layers for the S-box
def mat_apply(M, x):          # M = 8 rows, each an 8-bit mask; output bit i = parity(row_i & x)
    return sum(((bin(M[i] & x).count("1") & 1) << i) for i in range(8))
def mat_invertible(M):
    """GF(2) rank of the 8x8 matrix (rows as bit masks) == 8."""
    rows, rank = list(M), 0
    for bit in range(8):
        piv = next((i for i in range(rank, 8) if rows[i] >> bit & 1), None)
        if piv is None: continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        for i in range(8):
            if i != rank and rows[i] >> bit & 1: rows[i] ^= rows[rank]
        rank += 1
    return rank == 8

def keyed_sbox(A1, b1, A2, b2):
    """S'(x) = A2 * S_SM4(A1 * x + b1) + b2 over GF(2)^8. Affine-equivalent to the SM4 S-box, so the
    DDT and LAT spectra (DDT max 4, LAT max 16) are inherited exactly."""
    S = [mat_apply(A2, SM4_SBOX[mat_apply(A1, x) ^ b1]) ^ b2 for x in range(256)]
    inv = [0] * 256
    for i, v in enumerate(S): inv[v] = i
    return S, inv

def ddt_max(S):
    """max over a != 0, b of #{x : S[x] ^ S[x ^ a] == b}."""
    n = len(S); best = 0
    for a in range(1, n):
        cnt = [0] * n
        for x in range(n): cnt[S[x] ^ S[x ^ a]] += 1
        m = max(cnt)
        if m > best: best = m
    return best

def lat_max(S):
    """max over a, b != 0 of |#{x : a.x == b.S(x)} - n/2|, via a fast Walsh-Hadamard transform per output mask."""
    n = len(S); best = 0
    for b in range(1, n):
        w = [1 - 2 * (bin(b & S[x]).count("1") & 1) for x in range(n)]
        h = 1
        while h < n:
            for i in range(0, n, 2 * h):
                for j in range(i, i + h):
                    u, v = w[j], w[j + h]; w[j], w[j + h] = u + v, u - v
            h *= 2
        m = max(abs(x) for x in w[1:]) // 2
        if m > best: best = m
    return best

# ---------------------------------------------------------------- schedule
class Schedule:
    """All per-message material, derived from seed AND nonce together (repair 5)."""
    def __init__(self, seed, nonce: bytes):
        seed = _seed_bytes(seed)
        if len(nonce) != NONCE_LEN: raise ValueError("nonce must be 16 bytes")
        self.mac_key = StaffSponge(b"M", seed, nonce).take(32)
        sp = StaffSponge(b"K", seed, nonce)
        self.rounds = []
        for r in range(NR):
            rk = bytes_to_grid(sp.take(BLOCK_LEN))                       # 128-byte round key as a 16x8 byte grid
            A1 = A2 = None
            while A1 is None or not mat_invertible(A1): A1 = list(sp.take(8))   # resample until invertible
            while A2 is None or not mat_invertible(A2): A2 = list(sp.take(8))
            b1, b2 = sp.take(2)
            S, SI = keyed_sbox(A1, b1, A2, b2)
            SH = [sp.below(8) for _ in range(NF)]                        # face rotations (staves)
            SV = [sp.below(16) for _ in range(NB)]                       # beat-column rotations
            sigma = [sp.perm(NB) for _ in range(NF)]                     # staff butterfly beat order per face
            bridge = sp.perm(64)                                         # inner cell c <-> outer cell bridge[c]
            # Late coloring is squeezed only AFTER the existing round material.
            while True:
                A3 = A4 = None
                while A3 is None or not mat_invertible(A3): A3 = list(sp.take(8))
                while A4 is None or not mat_invertible(A4): A4 = list(sp.take(8))
                b3, b4 = sp.take(2)
                S2, SI2 = keyed_sbox(A3, b3, A4, b4)
                if S2 != S: break
            self.rounds.append(dict(S2=S2, SI2=SI2, A3=A3, A4=A4, b3=b3, b4=b4, rk=rk, S=S, SI=SI, A1=A1, A2=A2, b1=b1, b2=b2,
                                    SH=SH, SV=SV, sigma=sigma, bridge=bridge))
        self.white = bytes_to_grid(sp.take(BLOCK_LEN))
    def material(self) -> bytes:
        """Serialized round keys + whitening (for avalanche tests)."""
        return b"".join(grid_to_bytes(rk["rk"]) for rk in self.rounds) + grid_to_bytes(self.white)

# ---------------------------------------------------------------- two-cell mix (SM4 field; triplets stay integer)
MIX2_MATRIX = ((1, 1), (1, 2))
FIELD_POLY = 0x1F5

def mix2(u, v): return bar_apply(MIX2_MATRIX, u, v)
def mix2_inv(a, b): return bar_apply(MIX2_INV, a, b)

# ---------------------------------------------------------------- face-beat weave (N1 flavor, unchanged)
def weave(g, SH, SV):
    g = [g[f][SH[f]:] + g[f][:SH[f]] for f in range(NF)]
    out = [[0] * NB for _ in range(NF)]
    for b in range(NB):
        for f in range(NF): out[(f + SV[b]) % NF][b] = g[f][b]
    return out
def unweave(g, SH, SV):
    tmp = [[0] * NB for _ in range(NF)]
    for b in range(NB):
        for f in range(NF): tmp[f][b] = g[(f + SV[b]) % NF][b]
    return [tmp[f][-SH[f]:] + tmp[f][:-SH[f]] if SH[f] else tmp[f][:] for f in range(NF)]

# ---------------------------------------------------------------- staff butterfly (along each face)
LAYERS = (1, 2, 4)     # pair beat-order positions i and i^1, then i^2, then i^4: 3 matchings x 4 pairs per face
def staff_mix(g, sigma):
    g = [row[:] for row in g]
    for f in range(NF):
        s, row = sigma[f], g[f]
        for m in LAYERS:
            for i in range(NB):
                if i & m: continue
                a, b = s[i], s[i | m]
                row[a], row[b] = mix2(row[a], row[b])
    return g
def staff_unmix(g, sigma):
    g = [row[:] for row in g]
    for f in range(NF):
        s, row = sigma[f], g[f]
        for m in reversed(LAYERS):
            for i in range(NB):
                if i & m: continue
                a, b = s[i], s[i | m]
                row[a], row[b] = mix2_inv(row[a], row[b])
    return g

# ---------------------------------------------------------------- cross-staff dual-octahedron matchings
# Fixed order: opposite, radial, adjacent, then a partial bridge matching joining both components.
# Matching beats only; lower staff index is always the first mix2 argument.
CROSS_OPPOSITE = ((0,4), (1,5), (2,6), (3,7), (8,12), (9,13), (10,14), (11,15))
CROSS_RADIAL = tuple((f, f + 8) for f in range(8))
CROSS_ADJACENT = tuple((f, f + 1) for f in range(0, 16, 2))
CROSS_BRIDGE = ((1,2), (5,6), (9,10), (13,14))  # intentionally only four disjoint pairs
CROSS_LAYERS = (CROSS_OPPOSITE, CROSS_RADIAL, CROSS_ADJACENT, CROSS_BRIDGE)

def cross_staff_mix(g):
    """Copy and mix matching beats: opposite -> radial -> adjacent -> bridge, after each rehair."""
    g = [row[:] for row in g]
    for matching in CROSS_LAYERS:
        for f, h in matching:
            f, h = sorted((f, h))
            for t in range(NB): g[f][t], g[h][t] = mix2(g[f][t], g[h][t])
    return g

def cross_staff_unmix(g):
    """Undo cross-staff layers in reverse order, without mutating the input."""
    g = [row[:] for row in g]
    for matching in reversed(CROSS_LAYERS):
        for f, h in matching:
            f, h = sorted((f, h))
            for t in range(NB): g[f][t], g[h][t] = mix2_inv(g[f][t], g[h][t])
    return g

# ---------------------------------------------------------------- bar lines (five per staff, four measures of 2/4)
# Bar lines sit at beat boundaries 0, 2, 4, 6, 8 of each open 8-beat staff: | 0 1 | 2 3 | 4 5 | 6 7 |.
# B0 is a keyed Latin pair (field step, then the round's S and S2); the other six pairs use GF(2^8),
# SM4 polynomial 0x1F5 (nonzero field determinants). Applied in bar order B0..B4
# (pairs overlap at beats 1 and 6, so order matters); decrypt applies the inverses in reverse order.
# Plus two interior measure joins M2 (2,3) and M3 (4,5) so every adjacent pair 0-1..6-7 is mixed; 7 mixes total,
# applied in beat order B0,B1,M2,B2,M3,B3,B4 (mid-round bars AND the encore). No end-to-end loop: beat 7 is never paired with beat 0.
BARS = (                                   # (name, boundary, (i, j), matrix [[a, b], [c, d]]) : field products and XOR sums
    ("B0 start",  0, (0, 1), ((1, 5), (1, 6))),  # historical matrix retained, NEVER applied
    ("B1 bar 2",  2, (1, 2), ((1, 1), (1, 2))),
    ("M2 beats 3-4", 3, (2, 3), ((3, 5), (1, 2))),   # interior measure join (not a bar line)
    ("B2 center", 4, (3, 4), ((1, 3), (1, 4))),
    ("M3 beats 5-6", 5, (4, 5), ((5, 2), (2, 1))),   # interior measure join (not a bar line)
    ("B3 bar 6",  6, (5, 6), ((2, 1), (1, 1))),
    ("B4 end",    8, (6, 7), ((3, 1), (2, 1))),
)
def _gf_mul_raw(a, b):
    """Polynomial multiplication modulo SM4's x^8+x^7+x^6+x^5+x^4+x^2+1."""
    out = 0
    for _ in range(8):
        if b & 1: out ^= a
        a = ((a << 1) ^ (FIELD_POLY if a & 0x80 else 0)) & 255
        b >>= 1
    return out

# Byte lookup avoids repeated polynomial reductions in every pair pass.
_GF_MUL = tuple(bytes(_gf_mul_raw(a, b) for b in range(256)) for a in range(256))
def gf_mul(a, b): return _GF_MUL[a][b]
def gf_inv(a):
    """Multiplicative inverse in the SM4 field; zero has no inverse."""
    if not a: raise ValueError("zero has no field inverse")
    out, base, power = 1, a, 254
    while power:
        if power & 1: out = gf_mul(out, base)
        base = gf_mul(base, base)
        power >>= 1
    return out

def bar_det(M): return gf_mul(M[0][0], M[1][1]) ^ gf_mul(M[0][1], M[1][0])
def bar_inv(M):
    """Field adjugate: minus equals plus in characteristic two."""
    di = gf_inv(bar_det(M))
    return ((gf_mul(M[1][1], di), gf_mul(M[0][1], di)),
            (gf_mul(M[1][0], di), gf_mul(M[0][0], di)))
MIX2_INV = bar_inv(MIX2_MATRIX)
BARS_INV = tuple(bar_inv(M) for _, _, _, M in BARS)
def bar_apply(M, u, v):
    return (gf_mul(M[0][0], u) ^ gf_mul(M[0][1], v),
            gf_mul(M[1][0], u) ^ gf_mul(M[1][1], v))
# Keyed Latin pair (B0 and the four odd-rehair pairs). Field step = MIX2_MATRIX ((1,1),(1,2)),
# then one keyed bijective S-box per output cell. round_enc passes the round's S (u') and S2 (v').
# A change in u alone changes x and y by the same nonzero d; a change in v alone changes x by d
# and y by gf_mul(2,d) != 0. Bijective S-boxes keep both changes, so a one-input change always
# changes BOTH outputs (for every pair of tables). Two-input changes can still cancel one output.
def latin_pair(u, v, Sa, Sb):
    """x = u ^ v, y = u ^ gf_mul(2, v); return (Sa[x], Sb[y])."""
    x, y = u ^ v, u ^ gf_mul(2, v)
    return Sa[x], Sb[y]

def latin_unpair(u, v, SIa, SIb):
    """Inverse: x = SIa[u], y = SIb[v]; x ^ y = gf_mul(3, v), so v = gf_mul(gf_inv(3), x ^ y); u = x ^ v."""
    x, y = SIa[u], SIb[v]
    v = gf_mul(gf_inv(3), x ^ y)
    return x ^ v, v

def b0_apply(u, v, Sa, Sb):
    """Keyed B0: Latin pair with the caller's tables (round S for u', round S2 for v')."""
    return latin_pair(u, v, Sa, Sb)

def b0_unapply(u, v, SIa, SIb):
    return latin_unpair(u, v, SIa, SIb)

def bar_mix(g, Sa, Sb):
    g = [row[:] for row in g]
    for row in g:
        for name, _, (i, j), M in BARS:
            row[i], row[j] = b0_apply(row[i], row[j], Sa, Sb) if name == "B0 start" else bar_apply(M, row[i], row[j])
    return g
def bar_unmix(g, SIa, SIb):
    g = [row[:] for row in g]
    for row in g:
        for k in range(len(BARS) - 1, -1, -1):
            i, j = BARS[k][2]
            row[i], row[j] = b0_unapply(row[i], row[j], SIa, SIb) if BARS[k][0] == "B0 start" else bar_apply(BARS_INV[k], row[i], row[j])
    return g

# ---------------------------------------------------------------- overlapping triplets (open staffs, Z/256Z)
# Every adjacent window of three beats, in ascending order; never wrap 7 to 0.
# Small det-1 matrices found by search. Each row/column has >=2 odd entries.
# Thus a nonzero difference in any ONE input changes >=2 outputs, for all values:
# odd multiplication is a unit mod 256. This is not an all-odd/MDS matrix claim.
TRIPLETS = (
    ("T0", (0, 1, 2), ((5, 1, 1), (2, 3, 1), (5, 5, 2))),
    ("T1", (1, 2, 3), ((1, 3, 1), (3, 5, 2), (3, 2, 1))),
    ("T2", (2, 3, 4), ((2, 1, 1), (1, 3, 1), (3, 3, 2))),
    ("T3", (3, 4, 5), ((3, 3, 1), (2, 5, 3), (1, 3, 2))),
    ("T4", (4, 5, 6), ((1, 1, 1), (1, 3, 2), (3, 2, 3))),
    ("T5", (5, 6, 7), ((2, 1, 3), (3, 1, 3), (1, 2, 5))),
)
def triplet_det(M):
    a, b, c = M[0]; d, e, f = M[1]; g, h, i = M[2]
    return (a * (e*i - f*h) - b * (d*i - f*g) + c * (d*h - e*g)) & 255

def triplet_inv(M):
    """Adjugate/determinant inverse over Z/256Z (determinant must be odd)."""
    di = pow(triplet_det(M), -1, 256)
    cof = []
    for i in range(3):
        row = []
        for j in range(3):
            minor = [[M[r][c] for c in range(3) if c != j] for r in range(3) if r != i]
            row.append((-1 if (i+j) & 1 else 1) * (minor[0][0]*minor[1][1] - minor[0][1]*minor[1][0]))
        cof.append(row)
    return tuple(tuple(cof[j][i] * di & 255 for j in range(3)) for i in range(3))

TRIPLETS_INV = tuple(triplet_inv(M) for _, _, M in TRIPLETS)
def triplet_apply(M, u, v, w):
    return tuple((a*u + b*v + c*w) & 255 for a, b, c in M)
def triplet_mix(g):
    g = [row[:] for row in g]
    for row in g:
        for _, (i, j, k), M in TRIPLETS:
            row[i], row[j], row[k] = triplet_apply(M, row[i], row[j], row[k])
    return g
def triplet_unmix(g):
    g = [row[:] for row in g]
    for row in g:
        for t in range(len(TRIPLETS) - 1, -1, -1):
            i, j, k = TRIPLETS[t][1]
            row[i], row[j], row[k] = triplet_apply(TRIPLETS_INV[t], row[i], row[j], row[k])
    return g

# ---------------------------------------------------------------- bow pressure (one open staff; pressure READ may wrap)
BOW_STROKES = ((0, 1, 2), (2, 3, 4), (4, 5, 0), (6, 7, 0),
               (1, 2, 3), (3, 4, 5), (5, 6, 0))
# Beat-7 fix (2026-11-09): the last stroke used to read its pressure from beat 7 ((5,6,7)). A beat-7-only
# change then also changed that stroke's rotations, so beat 5 could come out unchanged and the whole bow
# delta stayed inside rehair pair (6,7); when that two-cell delta hit the pair's field kernel (du=dv or
# du=2dv) the rehair left a single changed byte. With pressure read from beat 0 (never written after
# stroke (0,1,2)), a beat-7 change reaches beat 6 in (6,7,0) and then ALWAYS changes beat 5 in (5,6,0)
# (fixed rotation, u fixed, v changed), so the delta spans pairs (4,5) and (6,7). Beats 1, 3, 5 keep the
# same no-singleton argument (see SPEC.md "Bow pressure"). Strokes and unbow order are otherwise unchanged.
# Beat-6 fix (2026-11-09, after attacks_octavo_beat7): the third stroke used to read its pressure from beat 6
# ((4,5,6)). A beat-6-only change then changed that stroke's r2, shifted beat 5, and (5,6,0) could cancel the
# shift again, leaving a delta du=2dv inside rehair pair (6,7) -> one changed byte (~1e-6 of beat-6 changes).
# Now (4,5,0): beat 6 is read by no stroke before (6,7,0); there (fixed rotations) beat 7 always changes and
# is never written again, and (5,6,0) (fixed rotations) adds the changed beat 6 into an unchanged beat 5, so
# beats 5 and 7 both change -> the delta spans pairs (4,5) and (6,7). Cost: beat 0 now feeds the rotations of
# three strokes ((4,5,0), (6,7,0), (5,6,0)); bow-alone best beat-6 differential ~2^-7.75 -> ~2^-5.68 (the
# rehair S-boxes absorb it). Even beats 0, 2, 4 are covered by measurement only, not by this argument.
# Beat-0 pressure-rotation fix (2026-11-09, after attacks_octavo_beat6 §6): BOW_STROKES unchanged, but each
# beat-0 reader gets a different view of the pressure byte before the r1/r2 formulas. (4,5,0) uses p,
# (6,7,0) uses rotl8(p,3), (5,6,0) uses rotl8(p,5). Other strokes keep rot 0 (identity). Singleton
# arguments that only need "pressure unchanged => rotations fixed" still hold; beat 0 is not written after
# stroke 1, so the bow stays invertible. Lab screen: bow-alone best diffs beat 7/6/0 ~2^-4.7/2^-5.6/2^-8.1
# -> ~2^-7.4/2^-7.1/2^-10.2; integrals/cubes of fixed-rotation ARX are not removed.
BOW_ROT_BASE, BOW_ROT_MOD, BOW_R2_SHIFT = 1, 7, 3
# Per-stroke left-rotate of the pressure byte BEFORE r1/r2, aligned with BOW_STROKES. Non-beat-0 readers
# use 0 (identity). The three beat-0 readers use 0, 3, 5 so they no longer share identical (r1, r2).
BOW_PRESSURE_ROT = (0, 0, 0, 3, 0, 0, 5)

def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 255

def bow_stroke(u, v, p):
    r1 = BOW_ROT_BASE + (p % BOW_ROT_MOD)
    r2 = BOW_ROT_BASE + ((p >> BOW_R2_SHIFT) % BOW_ROT_MOD)
    u = (u + rotl8(v, r1)) & 255
    v = v ^ rotl8(u, r2)
    return u, v

def unbow_stroke(u, v, p):
    r1 = BOW_ROT_BASE + (p % BOW_ROT_MOD)
    r2 = BOW_ROT_BASE + ((p >> BOW_R2_SHIFT) % BOW_ROT_MOD)
    v = v ^ rotl8(u, r2)
    u = (u - rotl8(v, r1)) & 255
    return u, v

def bow_pressure(staff):
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for (i, j, p), k in zip(BOW_STROKES, BOW_PRESSURE_ROT):
        s[i], s[j] = bow_stroke(s[i], s[j], rotl8(s[p], k))
    return s

def unbow_pressure(staff):
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for (i, j, p), k in zip(reversed(BOW_STROKES), reversed(BOW_PRESSURE_ROT)):
        s[i], s[j] = unbow_stroke(s[i], s[j], rotl8(s[p], k))
    return s

# ---------------------------------------------------------------- odd-beat rehair (open staff, no pressure read)
def odd_restack(staff, Sa, Sb):
    """Copy; keyed Latin pair on each odd beat and its previous even neighbor, never (7,0)."""
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for t in (1, 3, 5, 7):
        s[t-1], s[t] = latin_pair(s[t-1], s[t], Sa, Sb)
    return s

def unodd_restack(staff, SIa, SIb):
    s = list(staff)
    if len(s) != NB: raise ValueError("staff must have 8 bytes")
    for t in (7, 5, 3, 1):
        s[t-1], s[t] = latin_unpair(s[t-1], s[t], SIa, SIb)
    return s

# Key-signature code coverage. MIX_CODE_ROOTS are the public entry points. mix_code_closure()
# walks, on EVERY call, the source of each reachable module-level function/class (ast.Name
# references resolved in this module's CURRENT globals), so a replaced function and any new
# module-level helper it names are followed. MIX_CODE_FUNCS is the explicit, ordered list of
# what the closure reaches today (a test asserts equality); mix_description() hashes the list
# plus anything extra the live closure finds. Module-level data reached by the closure
# (BARS, TRIPLETS, CROSS_*, BOW_*, SM4_SBOX, _GF_MUL, sizes, ...) is canonically encoded and
# hashed too. Unencodable data or unreadable source fails closed (raises), never silently skips.
# Limits (honest): this is source attestation of the running process, not runtime integrity.
# It cannot see C-level/interpreter changes, the stdlib (hashlib, hmac, os, json, inspect, ast),
# helpers defined in OTHER modules that a foreign replacement function calls, mutation of
# objects inside a function's runtime state, code whose __code__ differs from the file
# inspect reads, or an attacker who also patches inspect/mix_description consistently.
MIX_CODE_ROOTS = ("encrypt", "decrypt", "siv_nonce", "key_signature", "split_blob")
MIX_CODE_FUNCS = (
    "bar_mix", "bar_unmix", "triplet_mix", "triplet_unmix", "triplet_apply",
    "triplet_det", "triplet_inv", "bow_pressure", "unbow_pressure",
    "bow_stroke", "unbow_stroke", "rotl8", "cross_staff_mix", "cross_staff_unmix",
    "odd_restack", "unodd_restack", "b0_apply", "b0_unapply", "latin_pair", "latin_unpair",
    "round_enc", "round_dec", "mix2", "mix2_inv",
    "bar_apply", "bar_inv", "bar_det", "gf_mul", "gf_inv", "_gf_mul_raw",
    # added 2026-11-09 (signature-gap fix): everything else round_enc/round_dec, the schedule,
    # the block encoding, whitening, SIV nonce, MAC and the attestation itself reach.
    "staff_mix", "staff_unmix", "shell_mix", "shell_unmix", "weave", "unweave", "xor_grid",
    "encrypt_grid", "decrypt_grid", "bytes_to_grid", "grid_to_bytes", "encode_block",
    "Schedule", "StaffSponge", "keyed_sbox", "mat_apply", "mat_invertible",
    "staff_clef", "siv_nonce", "_tag", "encrypt", "decrypt", "split_blob",
    "key_signature", "mix_description", "mix_code_closure", "_referenced_globals", "_canon_data",
    "_seed_bytes", "load_seed", "AuthError", "DecodeError",
)

def _referenced_globals(obj):
    """Every bare name in obj's source (ast.Name); resolution happens in mix_code_closure."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(obj)))
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}

def mix_code_closure(roots=None):
    """(code names, data names) of module globals reachable from roots, recomputed per call."""
    g = globals(); code, data = set(), set()
    todo = list(MIX_CODE_ROOTS if roots is None else roots)
    while todo:
        name = todo.pop()
        if name in code or name in data or name not in g: continue
        obj = g[name]
        if isinstance(obj, types.ModuleType): continue
        if isinstance(obj, (types.FunctionType, type)):
            code.add(name); todo.extend(sorted(_referenced_globals(obj)))
        else:
            data.add(name)
    return code, data

def _canon_data(x):
    """Canonical text for module data: None/bool/int/str/bytes, tuples, lists, str-keyed dicts."""
    if x is None or isinstance(x, (bool, int, str, bytes)): return type(x).__name__ + ":" + repr(x)
    if isinstance(x, (tuple, list)): return type(x).__name__ + "[" + ",".join(_canon_data(y) for y in x) + "]"
    if isinstance(x, dict): return "dict{" + ",".join(_canon_data(k) + "=" + _canon_data(x[k]) for k in sorted(x)) + "}"
    raise TypeError("cannot attest object of type " + type(x).__name__)

def mix_description():
    """Canonical ASCII JSON of parameters and listed mix function sources.
    Source is recomputed on each call; unavailable source fails closed, not silent.
    Length-framed names and sources make the digest unambiguous and stable.
    """
    reach, data_names = mix_code_closure()
    funcs = tuple(MIX_CODE_FUNCS) + tuple(sorted(reach - set(MIX_CODE_FUNCS)))
    code = hashlib.sha256()
    for name in funcs:
        obj = globals()[name]
        if not isinstance(obj, (types.FunctionType, type)): raise TypeError(name + " is not an attestable Python function/class")
        defaults = _canon_data((getattr(obj, "__defaults__", None), getattr(obj, "__kwdefaults__", None)))
        for part in (name.encode("utf-8"), inspect.getsource(obj).encode("utf-8"), defaults.encode("utf-8")):
            code.update(len(part).to_bytes(8, "big")); code.update(part)
    data = hashlib.sha256()
    for name in sorted(data_names):
        for part in (name.encode("utf-8"), _canon_data(globals()[name]).encode("utf-8")):
            data.update(len(part).to_bytes(8, "big")); data.update(part)
    bars = [dict(name=name, boundary=boundary, pair=pair, kind="field+keyed-sbox",
                 field=MIX2_MATRIX, tables="u'=S[x];v'=S2[y];inverse SI,SI2") if name == "B0 start" else
            dict(name=name, boundary=boundary, pair=pair, kind="GF(2^8)", matrix=M)
            for name, boundary, pair, M in BARS]
    return json.dumps(dict(bars=bars, triplets=TRIPLETS, mix2=MIX2_MATRIX,
        mix_code=dict(functions=funcs, roots=MIX_CODE_ROOTS, sha256=code.hexdigest(),
                      framing="per function: name, source, canonical defaults; each UTF-8 part prefixed by uint64be length"),
        mix_data=dict(names=tuple(sorted(data_names)), sha256=data.hexdigest(),
                      framing="per name (sorted): name, _canon_data(value); each UTF-8 part prefixed by uint64be length"),
        field_poly=FIELD_POLY, pair_ring="GF(2^8); B0 keyed Latin pair", triplet_ring="Z/256Z",
        bow=dict(strokes=BOW_STROKES, pressure_rot=BOW_PRESSURE_ROT,
                 rot_base=BOW_ROT_BASE, rot_mod=BOW_ROT_MOD, r2_shift=BOW_R2_SHIFT,
                 formula="view=rotl8(p,pressure_rot[stroke]);r1=base+view%mod;r2=base+(view>>shift)%mod;u=(u+rotl8(v,r1))&255;v=v^rotl8(u,r2)",
                 placement="after-mid-triplets-before-rehair;after-encore-triplets-before-rehair"),
        odd_restack=dict(beats=(1,3,5,7), pairs=((0,1),(2,3),(4,5),(6,7)),
                 kind="field+keyed-sbox", field=MIX2_MATRIX, tables="u'=S[x];v'=S2[y];inverse SI,SI2",
                 formula="x=u^v;y=u^gf_mul(2,v);u'=S[x];v'=S2[y]",
                 placement="after-each-bow-before-cross"),
        cross_staff=dict(opposite=CROSS_OPPOSITE, radial=CROSS_RADIAL,
                 adjacent=CROSS_ADJACENT, bridge=CROSS_BRIDGE, layers=CROSS_LAYERS,
                 order="opposite;radial;adjacent;bridge", orientation="lower-index-first",
                 beats="matching-beats-0..7", operation="mix2",
                 placement="after-mid-rehair-before-S2;after-encore-rehair")),
        sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def key_signature(seed=None):
    """Seed-keyed commitment to this process's score; not a blob field or API override."""
    return StaffSponge(b"G", _seed_bytes(seed), mix_description()).take(16)

# ---------------------------------------------------------------- shell bridges (inner <-> outer)
def shell_mix(g, bridge, r):
    """64 disjoint pairs: inner cell c=(f,t), f<8, with outer cell bridge[c]. The 'u' side alternates
    by round (even: inner, odd: outer) — N1's alternating-shell idea kept as orientation."""
    g = [row[:] for row in g]
    for c in range(64):
        fi, ti = divmod(c, NB); fo, to = divmod(bridge[c], NB); fo += 8
        if r % 2 == 0: g[fi][ti], g[fo][to] = mix2(g[fi][ti], g[fo][to])
        else:          g[fo][to], g[fi][ti] = mix2(g[fo][to], g[fi][ti])
    return g
def shell_unmix(g, bridge, r):
    g = [row[:] for row in g]
    for c in range(64):
        fi, ti = divmod(c, NB); fo, to = divmod(bridge[c], NB); fo += 8
        if r % 2 == 0: g[fi][ti], g[fo][to] = mix2_inv(g[fi][ti], g[fo][to])
        else:          g[fo][to], g[fi][ti] = mix2_inv(g[fo][to], g[fi][ti])
    return g

# ---------------------------------------------------------------- round
def xor_grid(g, k): return [[g[f][t] ^ k[f][t] for t in range(NB)] for f in range(NF)]

def round_enc(g, rk, r):
    g = xor_grid(g, rk["rk"])                                            # 1. add round key
    S = rk["S"]; g = [[S[x] for x in row] for row in g]                  # 2. SubBytes (keyed 8-bit S-box), all 128 cells
    g = weave(g, rk["SH"], rk["SV"])                                     # 3. face-beat weave
    g = staff_mix(g, rk["sigma"])                                        # 4. staff butterfly (within faces)
    g = shell_mix(g, rk["bridge"], r)                                    # 5. shell bridges (across shells)
    g = bar_mix(g, rk["S"], rk["S2"])                                    # 6. seven named pair mixes
    g = triplet_mix(g)                                                  # 7. six overlapping triplets
    g = [bow_pressure(row) for row in g]                                 # nonlinear mid-stack restack
    g = [odd_restack(row, rk["S"], rk["S2"]) for row in g]                                  # lighter odd-beat rehair
    g = cross_staff_mix(g)                                              # between staffs, before S2
    S2 = rk["S2"]; g = [[S2[x] for x in row] for row in g]               # 8. late second coloring
    g = bar_mix(g, rk["S"], rk["S2"])                                    # 9. pair-mix encore
    g = triplet_mix(g)                                                  # 10. triplet encore
    g = [bow_pressure(row) for row in g]                                 # nonlinear encore restack
    g = [odd_restack(row, rk["S"], rk["S2"]) for row in g]                                  # encore rehair
    return cross_staff_mix(g)

def round_dec(g, rk, r):
    g = cross_staff_unmix(g)                                            # undo encore cross FIRST
    g = [unodd_restack(row, rk["SI"], rk["SI2"]) for row in g]
    g = [unbow_pressure(row) for row in g]
    g = triplet_unmix(g)                                                # undo encore triplets FIRST
    g = bar_unmix(g, rk["SI"], rk["SI2"])                                # then encore bars
    SI2 = rk["SI2"]; g = [[SI2[x] for x in row] for row in g]
    g = cross_staff_unmix(g)                                            # undo mid cross
    g = [unodd_restack(row, rk["SI"], rk["SI2"]) for row in g]
    g = [unbow_pressure(row) for row in g]
    g = triplet_unmix(g)
    g = bar_unmix(g, rk["SI"], rk["SI2"])
    g = shell_unmix(g, rk["bridge"], r)
    g = staff_unmix(g, rk["sigma"])
    g = unweave(g, rk["SH"], rk["SV"])
    SI = rk["SI"]; g = [[SI[x] for x in row] for row in g]
    return xor_grid(g, rk["rk"])

def encrypt_grid(g, sch: Schedule, rounds=NR, white=True):
    for r in range(rounds): g = round_enc(g, sch.rounds[r], r)
    return xor_grid(g, sch.white) if white else g
def decrypt_grid(g, sch: Schedule, rounds=NR):
    g = xor_grid(g, sch.white)
    for r in range(rounds - 1, -1, -1): g = round_dec(g, sch.rounds[r], r)
    return g

# ---------------------------------------------------------------- encoding: 128 bytes <-> 16 faces x 8 byte-beats
def bytes_to_grid(b: bytes):
    if len(b) != BLOCK_LEN: raise ValueError("block must be 128 bytes")
    return [list(b[8 * f: 8 * f + 8]) for f in range(NF)]
def grid_to_bytes(g):
    return bytes(x for row in g for x in row)
def grid_rows(g):
    """each staff as two measures of four 2-digit hex bytes: 'AA BB CC DD | EE FF 00 11'"""
    return [" ".join(f"{x:02X}" for x in row[:4]) + " | " + " ".join(f"{x:02X}" for x in row[4:]) for row in g]

def encode_block(msg: bytes) -> bytes:
    if len(msg) > MAX_MSG: raise ValueError("message too long (max 127 bytes)")
    return bytes([len(msg)]) + msg + bytes(MAX_MSG - len(msg))

# ---------------------------------------------------------------- AE API
def staff_clef(seed=None) -> bytes:
    """seed-only clef: StaffSponge(b"C", seed, 16 zero bytes).take(16). Never stored in the blob."""
    return StaffSponge(b"C", _seed_bytes(seed), bytes(NONCE_LEN)).take(16)

def siv_nonce(msg: bytes, pickup: bytes, seed=None) -> bytes:
    """homemade SIV-style nonce = SHA-256(clef || pickup || encode_block(msg))[:16]"""
    pickup = bytes(pickup)
    if len(pickup) != PICKUP_LEN: raise ValueError("pickup must be 16 bytes")
    return hashlib.sha256(staff_clef(seed) + pickup + encode_block(bytes(msg))).digest()[:NONCE_LEN]

def _tag(mac_key, pickup, nonce, ct, clef, key_sig):
    return hmac.new(mac_key, clef + key_sig + VERSION + pickup + nonce + ct, hashlib.sha256).digest()

def encrypt(msg: bytes, seed=None, nonce: bytes = None) -> bytes:
    """blob = b"SN2" || pickup(16) || nonce(16) || ct(128) || HMAC-SHA256(mac_key, clef || key_sig || b"SN2" || pickup || nonce || ct).
    pickup = 16 fresh OS-random bytes every call (no public pickup argument, by design);
    nonce = SHA-256(clef || pickup || encode_block(msg))[:16]; a caller nonce must equal it (ValueError otherwise)."""
    msg = bytes(msg); block = encode_block(msg); clef = staff_clef(seed)
    pickup = os.urandom(PICKUP_LEN)
    syn = hashlib.sha256(clef + pickup + block).digest()[:NONCE_LEN]
    if nonce is not None and not hmac.compare_digest(bytes(nonce), syn):
        raise ValueError("nonce must be the synthetic (SIV) nonce for this message and pickup")
    nonce = syn
    sch = Schedule(seed, nonce)
    ct = grid_to_bytes(encrypt_grid(bytes_to_grid(block), sch))
    return VERSION + pickup + nonce + ct + _tag(sch.mac_key, pickup, nonce, ct, clef, key_signature(seed))

def split_blob(blob: bytes):
    """-> (version, pickup, nonce, ct, tag)"""
    return blob[:PK0], blob[PK0:N0], blob[N0:CT0], blob[CT0:CT1], blob[CT1:]

def decrypt(blob: bytes, seed=None) -> bytes:
    """Tag is checked FIRST (constant-time compare). On any mismatch: AuthError, no payload."""
    blob = bytes(blob)
    if len(blob) != BLOB_LEN: raise AuthError("bad blob length")
    v, pickup, nonce, ct, tag = split_blob(blob)
    if not hmac.compare_digest(v, VERSION): raise AuthError("bad version prefix")
    clef = staff_clef(seed); sch = Schedule(seed, nonce)
    if not hmac.compare_digest(tag, _tag(sch.mac_key, pickup, nonce, ct, clef, key_signature(seed))): raise AuthError("tag mismatch")
    b = grid_to_bytes(decrypt_grid(bytes_to_grid(ct), sch))
    L = b[0]                                   # secondary sanity check only; the MAC is the authenticity check
    if L > MAX_MSG or any(b[1 + L:]): raise DecodeError("tag valid but block malformed")
    msg = b[1:1 + L]
    if not hmac.compare_digest(nonce, hashlib.sha256(clef + pickup + encode_block(msg)).digest()[:NONCE_LEN]):
        raise AuthError("SIV nonce mismatch")
    return msg

def encrypt_hello(seed=None):
    blob = encrypt(b"hello world", seed)
    v, pk, n, ct, tag = split_blob(blob); g = bytes_to_grid(ct)
    return dict(blob=blob, pickup=pk, nonce=n, ct=ct, tag=tag, grid=g, rows=grid_rows(g))
