# Security

Octavo is an experimental, homemade cipher made for learning and for fun. It is not constant-time, and nothing here is a proof of security. An independent reviewer ([@liqdmetal](https://github.com/liqdmetal), [issue #1](https://github.com/Kromatikus/octavo/issues/1)) rebuilt the round function and reported no distinguisher, forgery or key recovery; that is a negative experimental result, not expert cryptanalysis and not a proof.

**Do not use Octavo to protect real data.** Use a vetted, well-reviewed tool such as AES-GCM-SIV (RFC 8452), [age](https://age-encryption.org), or [libsodium](https://doc.libsodium.org).

Found a weakness? That's the point of publishing it. Please open an issue with a description and, ideally, a script that reproduces it. Credible findings get added to [ATTACKS.md](ATTACKS.md) with credit.
