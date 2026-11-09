# octavo003 — frozen Octavo snapshot

Saved 2026-11-09 from live /workspace/sneak_n2 (Python caches excluded), plus sneak1024-seed.txt.

This is the packaging revision on top of octavo002 (beat-0 pressure rotation). The round function is unchanged.

- sneak_n2.py SHA-256: 127a9628c88fe9429bca7505a67aefb6b513106a3c1cd30d4d71a443354778cd
- EXPECTED_MIX_SHA256: d64f4e9ce02c88371f21dfd264b6d2ca1fe13c89e3fd93261caea02c703b77bd
- key_sig (demo seed): e5f54546ca530ee6103b8420578a6aca
- Tests at freeze: 245/245 (0 skipped on the author's machine)
- Blob size: 196 bytes (version byte 1 || SN2 || pickup || nonce || ct || tag)
- hello-world pickup ecd5b4a32534bbea72ae2bdaaa2bb589, nonce 408787444f355728a176e74ad1d69691
- Changes: module-relative seed path; cached/embedded key-signature digest; format version byte; weak-seed rejection; portable tests. Triggered by independent review in https://github.com/Kromatikus/octavo/issues/1 (@liqdmetal). Round function unchanged vs octavo002.
- Picture not redrawn.

Homemade, NOT for real secrets. Use AES-GCM-SIV, age, or libsodium.
