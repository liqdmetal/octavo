# Octavo attack history

Octavo was attacked ten times while it was designed, then independently reviewed. Each round looked for weaknesses, and the most serious finding was usually fixed before the next round. Only the latest full report is kept in this repo: [`attacks_octavo_beat6/`](attacks_octavo_beat6/REPORT.md). The older report folders are still in this repo's git history (first commit).

None of these rounds broke the full 16-round cipher. That is a negative experimental result, not a proof of security. **Octavo is homemade. For real secrets use AES-GCM-SIV, age, or libsodium.**

| # | Round | What it found | What changed afterwards |
|---|---|---|---|
| 1 | First N2 attack (512-bit era) | Not broken. N1's integrity hole and linear key-schedule seed leak were closed; distinguishers died by round 3–4 of 16. | Moved to 8-bit cells, bar mixes and a second coloring. |
| 2 | 8-bit cells, second coloring | No plaintext, seed or MAC break. Old-format blobs still verified, and 7 of 2,048 decrypted to different plaintext. | Added the clef in the MAC, the bar-line encore and an SIV-style nonce. |
| 3 | Clef, encore, SIV nonce | Fixes held. The encore only mixed within beat blocks, and identical messages gave identical blobs (dictionary attack with an oracle). | Joined beats 3–4 and 5–6 in the bar mixes. |
| 4 | Joined pairs | Joins worked. 1- and 2-round distinguishers remained; 0x80 differences slipped through one cell. | Added six triplets, field pair mixes over GF(2^8) and a random 16-byte pickup. |
| 5 | Pickup, field pairs, triplets | The pickup closed the guess-and-compare attack. A new short-round truncated trail remained. | Added the key signature, field mix2 and the bow-pressure restack. |
| 6 | Three leftover-shape fixes | All three fixes held; the 2-round sparse distinguisher was gone at test size. | Added the cross-staff mix, then the bridge, nonlinear B0, odd-beat restack and code key signature. |
| 7 | Four leftover changes | No break. ARX single-byte leaks in the bow and restack remained. | Replaced ARX in B0 and the restack with keyed Latin S-box pairs; closed a key-signature coverage gap. |
| 8 | Linear and algebraic | No break. S-boxes match SM4 linearity (2^-3); cross layer branch number 6; 5 bow single-byte leaks left on beat 7. | Bow stroke (5,6,7) changed to (5,6,0). |
| 9 | After the beat-7 fix | 0 critical/high/medium. Beat-6 single-byte leaks found. | Bow stroke (4,5,6) changed to (4,5,0). |
| 10 | After the beat-6 fix ([report](attacks_octavo_beat6/REPORT.md)) | 0 critical/high/medium, 4 low, 4 info. No single-byte leak on any beat. Most pressing: three strokes share beat 0's rotation. | Applied: each beat-0 reader now uses a different rotation (0, 3, 5 bits). Verified with 0 single-byte leaks on every beat in [`fix_beat0rot_verification/`](fix_beat0rot_verification/). Not yet attacked again. |
| 11 | Packaging revision (this snapshot) plus independent review ([issue #1](https://github.com/Kromatikus/octavo/issues/1) by [@liqdmetal](https://github.com/liqdmetal)) | No cipher break reported (rebuilt round function; ~535M probes). Packaging bugs: hardcoded seed path, stale attack-folder paths, `inspect.getsource` on every call, no version byte, weak seeds accepted. | Packaging only: module-relative seed, cached/embedded key signature, 1-byte format version (blobs are 196 bytes), weak-seed rejection, portable tests. Round function unchanged. |
