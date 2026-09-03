# Block cipher paddings

This directory contains the block-padding schemes ported from the Bouncy Castle
C# source tree at `crypto/src/crypto/paddings`.

Every scheme implements `tc_pad::BlockCipherPadding` and reports its name
through `tc_crypto::AlgorithmName` in place of `PaddingName`. Only a scheme that
actually needs a resource also implements `tc_pad::BlockCipherPaddingInit<P>`;
stateless schemes leave it out rather than accepting parameters they would
discard. Each crate re-exports `tc_pad::PaddingError`, so a caller that uses one
scheme does not have to depend on `tc_pad` directly.

## Implemented

| Status | Scheme | Crate and public API | Bouncy Castle C# type | Needs a generator |
|--------|--------|----------------------|-----------------------|-------------------|
| ✅ Done | Zero-byte | `tc_zero_pad::ZeroBytePadding` | `ZeroBytePadding` | No |
| ✅ Done | PKCS#7 / PKCS#5 | `tc_pkcs7_pad::Pkcs7Padding` | `Pkcs7Padding` | No |
| ✅ Done | ANSI X9.23 | `tc_x923_pad::X923Padding` | `X923Padding` without a random | No |
| ✅ Done | ISO 10126-2 | `tc_iso10126_pad::Iso10126Padding<R>` | `ISO10126d2Padding`, `X923Padding` with a random | Yes |
| ✅ Done | ISO 7816-4 | `tc_iso7816_pad::Iso7816d4Padding` | `ISO7816d4Padding` | No |
| ✅ Done | Trailing bit complement | `tc_tbc_pad::TbcPadding` | `TbcPadding` | No |

The Bouncy Castle `paddings` namespace holds eight files: these six schemes,
the `IBlockCipherPadding` interface (ported as `tc_pad`), and
`PaddedBufferedBlockCipher`, which remains to be implemented.

## Ready to implement

| Status | Bouncy Castle C# type | Available prerequisites |
|--------|-----------------------|-------------------------|
| 🟡 Ready | `PaddedBufferedBlockCipher` | `tc_buff::BufferedBlockCipher`, the block modes under `crypto/block_modes`, and all six padding schemes are now available. |

`PaddedBufferedBlockCipher` is the only consumer of these schemes in Bouncy
Castle. Until the padded buffering layer itself is implemented, callers can use
the schemes by driving `add_padding` and `pad_count` on a caller-owned block.

One design note for whoever writes that layer: Bouncy Castle's
`PaddedBufferedBlockCipher.Init` calls `padding.Init(random)` unconditionally,
which it can do because every C# padding implements the method. Here the bound
must be `S: BlockCipherPadding` alone — requiring `BlockCipherPaddingInit<P>`
too would exclude every stateless scheme. A padding that needs a generator is
initialized by the caller before being handed over.

## Deliberate differences from Bouncy Castle

| Area | Bouncy Castle | Here | Reason |
|------|---------------|------|--------|
| `PaddingName` | On the interface | `tc_crypto::AlgorithmName` | Keeps `tc_pad` free of dependencies, matching `tc_cipher` and `tc_macs`. Names match BC exactly (`PKCS7`, `X9.23`, `ISO10126-2`, `ISO7816-4`, `TBC`, `ZeroBytePadding`). |
| `Init(SecureRandom)` | On the interface, every scheme implements it | Separate `BlockCipherPaddingInit<P>`, implemented only by ISO 10126-2 | A blanket impl over any `P` would block type inference and over-claim what a stateless scheme accepts. |
| Randomized X9.23 | One `X923Padding` with an optional random | `X923Padding` (zeros) and `Iso10126Padding<R>` (random) | Random-filled X9.23 and ISO 10126-2 produce interchangeable blocks. Splitting them lets the type say whether a generator is required instead of deferring it to a null check. |
| Uninitialized use | Falls back to a default `SecureRandom` | `PaddingError::NotInitialised` | No ambient generator exists under `no_std`, and silently substituting one hides a caller mistake. |
| Oversized blocks | `(byte)(input.Length - inOff)` truncates | `PaddingError::UnsupportedBlockSize` | PKCS#7, X9.23, and ISO 10126-2 store the count in one byte and cannot serve blocks of 256 bytes or more. |
| TBC `PadCount` | Loop stops when the run ends | Branch-free full scan | Same result, constant time with respect to the block contents. |

## Constant-time behaviour

`pad_count` is the side of these schemes an attacker can reach with chosen
ciphertext, so every implementation walks the whole block with masked,
branch-free arithmetic and branches only on the aggregated result. Zero-byte,
PKCS#7, and ISO 7816-4 port the masked scans Bouncy Castle already uses; X9.23
and ISO 10126-2 use its branch-free range test; TBC improves on Bouncy Castle,
whose loop is variable-time.

Constant-time `pad_count` on its own does not make a protocol safe against
padding-oracle attacks. Padding must still be verified under a MAC, and callers
must not report padding failure separately from authentication failure.

## Verification

```bash
cargo test -p tc_pad -p tc_zero_pad -p tc_pkcs7_pad -p tc_x923_pad \
  -p tc_iso10126_pad -p tc_iso7816_pad -p tc_tbc_pad --locked
```

All crates are core-only `no_std`:

```bash
cargo build -p tc_pad -p tc_zero_pad -p tc_pkcs7_pad -p tc_x923_pad \
  -p tc_iso10126_pad -p tc_iso7816_pad -p tc_tbc_pad --locked
```
