"""Verifier for the octavo 1-round sparse-output differential challenge.

Goal: find a base 128-byte state X, a byte position p (0..127) and a nonzero
delta d (1..255) such that the one-round reduced cipher maps X and X^(p<-d)
to outputs that agree on at least 8 of the 128 bytes.

Submission (JSON file or stdin):
  {"base": "<256 hex chars = 128 bytes>", "position": 0..127, "delta": 1..255}

Run:  python verify.py submission.json
      python verify.py < submission.json

The verifier uses only sneak_n2.py and sneak1024-seed.txt in this folder, with
the fixed nonce from nonce.txt. Exit status 0 = accepted, 1 = rejected.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import sneak_n2 as N  # noqa: E402

THRESHOLD = 8
BLOCK_LEN = 128


def load_schedule():
    seed = N.load_seed(os.path.join(HERE, "sneak1024-seed.txt"))
    with open(os.path.join(HERE, "nonce.txt"), encoding="ascii") as f:
        nonce = bytes.fromhex(f.read().strip())
    return N.Schedule(seed, nonce)


def one_round(sch, x: bytes) -> bytes:
    """Single round of the live cipher on a 128-byte state (no whitening)."""
    return N.grid_to_bytes(N.round_enc(N.bytes_to_grid(x), sch.rounds[0], 0))


def check(sub, sch):
    """Return (accepted: bool, message: str)."""
    if not isinstance(sub, dict):
        return False, "submission must be a JSON object"
    try:
        base = bytes.fromhex(sub["base"])
        pos = sub["position"]
        delta = sub["delta"]
    except (KeyError, TypeError, ValueError) as e:
        return False, f"malformed submission: {e}"
    if len(base) != BLOCK_LEN:
        return False, f"base must be {BLOCK_LEN} bytes, got {len(base)}"
    if type(pos) is not int or not (0 <= pos < BLOCK_LEN):
        return False, "position must be an integer 0..127"
    if type(delta) is not int or not (1 <= delta <= 255):
        return False, "delta must be an integer 1..255"

    other = bytearray(base)
    other[pos] ^= delta
    other = bytes(other)

    y0 = one_round(sch, base)
    y1 = one_round(sch, other)
    unchanged = sum(1 for a, b in zip(y0, y1) if a == b)
    if unchanged >= THRESHOLD:
        return True, f"ACCEPTED: {unchanged}/128 output bytes unchanged (threshold {THRESHOLD})"
    return False, f"REJECTED: {unchanged}/128 output bytes unchanged (need >= {THRESHOLD})"


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            raw = f.read()
    else:
        raw = sys.stdin.read()
    try:
        sub = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"REJECTED: not valid JSON ({e})")
        return 1
    ok, msg = check(sub, load_schedule())
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
