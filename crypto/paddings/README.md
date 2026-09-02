# Block cipher paddings

This directory contains the block-padding schemes ported from the Bouncy
Castle C# source tree at `crypto/src/crypto/paddings`.

Every scheme implements `tc_pad::BlockCipherPadding` and reports its name
through `tc_crypto::AlgorithmName` in place of `PaddingName`. Only schemes that
actually need a resource, such as the generator used by ISO 10126-2, also
implement `tc_pad::BlockCipherPaddingInit<P>`; stateless schemes leave it out
rather than accepting parameters they would discard. Crates may additionally
expose inherent methods with tighter signatures than the traits allow.

| Status | Scheme | Crate and public API | Bouncy Castle C# type |
|--------|--------|----------------------|-----------------------|
| ✅ Done | Zero-byte padding | `tc_zero_pad::ZeroBytePadding` | `ZeroBytePadding` |
| ⬜ TODO | PKCS#7 / PKCS#5 | — | `Pkcs7Padding` |
| ⬜ TODO | ANSI X9.23 | — | `X923Padding` |
| ⬜ TODO | ISO 10126-2 | — | `ISO10126d2Padding` |
| ⬜ TODO | ISO 7816-4 | — | `ISO7816d4Padding` |
| ⬜ TODO | Trailing-bit complement | — | `TbcPadding` |
| ⬜ TODO | Padded buffered block cipher | — | `PaddedBufferedBlockCipher` |

Legend: ✅ completed, ⬜ TODO.

## Verification

```bash
cargo test -p tc_pad -p tc_zero_pad --locked
```
