# Challenge: 1-round sparse-output differential

Self-contained. Needs only Python 3 (standard library).

## Task

The reduced cipher is one round of `sneak_n2.py` (`round_enc`, key schedule round 0,
fixed nonce from `nonce.txt`, seed from `sneak1024-seed.txt`). It maps a 128-byte state
to a 128-byte state.

Find a base state `X`, a byte position `p` (0..127) and a nonzero delta `d` (1..255)
such that the one-round outputs of `X` and `X` with byte `p` XORed by `d` agree on
**at least 8 of the 128 bytes**.

## Submit

```json
{"base": "<256 hex chars>", "position": 0, "delta": 1}
```

```
python verify.py submission.json
```

Exit status 0 means accepted. Exit status 1 means rejected, with the reason printed.

## Baseline

Random pairs usually agree on about 0.5 bytes (mean 0.4976 over 262,144 pairs in the
recorded 1-round scan). The recorded maximum was 7 unchanged bytes. No submission
reaching 8 is known. The target is open, not a known break.

Reference: `attacks_octavo_beat6/attack_differential.py`, section 1 (historical; that
folder is pinned to an older revision and does not run on this tree).
