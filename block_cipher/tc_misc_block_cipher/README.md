# tc_misc_block_cipher

Less common block ciphers on the `tc_block_cipher` traits. Each algorithm is a
module behind its own feature, all off by default:

- `idea` — IDEA, `idea::IdeaEngine`.
- `noekeon` — Noekeon, `noekeon::NoekeonEngine`.
- `rijndael` — Rijndael with 128- to 256-bit blocks, `rijndael::RijndaelEngine` and its aliases.
- `skipjack` — SKIPJACK, `skipjack::SkipjackEngine`.
- `tea` — TEA and XTEA, `tea::TeaEngine` and `tea::XteaEngine`.

```toml
[dependencies]
tc_misc_block_cipher = { version = "0.1.0", features = ["idea"] }
```
