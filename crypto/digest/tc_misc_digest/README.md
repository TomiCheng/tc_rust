# tc_misc_digest

Less common message digests on the `tc_digest` traits. Each algorithm is a
module behind its own feature, all off by default:

- `haraka` — Haraka-256 and Haraka-512, `haraka::Haraka256Digest` and `haraka::Haraka512Digest`.
- `photon-beetle` — PHOTON-Beetle-Hash, `photon_beetle::PhotonBeetleDigest`.
- `sparkle` — ESCH-256 and ESCH-384, `sparkle::SparkleDigest`.
- `tiger` — Tiger, `tiger::TigerDigest`.
- `whirlpool` — Whirlpool, `whirlpool::WhirlpoolDigest`.
- `xoodyak` — Xoodyak Hash, `xoodyak::XoodyakDigest`.

With `std`, Haraka selects AES-NI at runtime on x86 and x86-64; without it,
Haraka uses the portable backend.

```toml
[dependencies]
tc_misc_digest = { version = "0.1.0", features = ["whirlpool"] }
```
