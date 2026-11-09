"""Shared helpers for beat-0rot verification. Imports live sneak_n2; asserts SHA + BOW_PRESSURE_ROT."""
import hashlib, json, math, os, sys, time
from pathlib import Path
import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
LIVE = REPO / 'sneak_n2.py'
EXPECTED_SHA = None  # filled after reading live file; scripts record actual
sys.path.insert(0, str(REPO))
import sneak_n2 as N

LIVE_SHA = hashlib.sha256(LIVE.read_bytes()).hexdigest()
assert N.BOW_STROKES == ((0,1,2),(2,3,4),(4,5,0),(6,7,0),(1,2,3),(3,4,5),(5,6,0))
assert N.BOW_PRESSURE_ROT == (0,0,0,3,0,0,5)
assert N.BOW_ROT_BASE == 1 and N.BOW_ROT_MOD == 7 and N.BOW_R2_SHIFT == 3
assert len(N.BOW_PRESSURE_ROT) == len(N.BOW_STROKES)

# Pre-fix live bow-alone best diffs from attacks_octavo_beat6 REPORT.md
PRE_FIX_BEST = {0: -8.1, 6: -5.6, 7: -4.9}

def now():
    return time.strftime('%Y-%m-%d %H:%M:%S %Z')

def rotl(x, r):
    r = np.asarray(r, dtype=np.int64)
    x = np.asarray(x, dtype=np.int64)
    return ((x << r) | (x >> (8 - r))) & 255

def u8bow(x):
    """Vectorised live bow including BOW_PRESSURE_ROT."""
    x = np.asarray(x, dtype=np.int32).copy()
    for (i, j, p), k in zip(N.BOW_STROKES, N.BOW_PRESSURE_ROT):
        pp = rotl(x[:, p], k)
        r1 = N.BOW_ROT_BASE + (pp % N.BOW_ROT_MOD)
        r2 = N.BOW_ROT_BASE + ((pp >> N.BOW_R2_SHIFT) % N.BOW_ROT_MOD)
        v = x[:, j]
        u = (x[:, i] + rotl(v, r1)) & 255
        x[:, i] = u
        x[:, j] = v ^ rotl(u, r2)
    return x

def validate_fast_bow(n=2000, seed=42):
    rng = np.random.default_rng(seed)
    X = rng.integers(0, 256, (n, 8), dtype=np.int32)
    Y = u8bow(X)
    for i in range(n):
        assert list(map(int, Y[i])) == N.bow_pressure(list(map(int, X[i])))
    return n

G2 = np.array([N.gf_mul(2, x) for x in range(256)], dtype=np.int32)

def save(name, obj):
    path = HERE / f'{name}_results.json'
    path.write_text(json.dumps(obj, indent=2, default=int))
    return path
