# tc_digest

Message-digest (hash) algorithms, ported from the Bouncy Castle C# library
(`bc-csharp`, `crypto/digests/`) as a **learning project**.

Each algorithm implements the `TryDigest` / `Digest` traits from
[`tc_crypto_core`](../tc_crypto_core). The real hashes are pure fixed-size bit/byte
computation and the crate depends **only** on `tc_crypto_core` — never on `tc_math`
(hashes carry no big-integer arithmetic). The default `std` feature enables runtime
CPU-feature dispatch; disable default features for `no_std`. It uses `alloc` for the
one pass-through case (`NullDigest`, which buffers arbitrary-length input); every
other digest is alloc-free.

## Design notes

- **`MdBuffer<const N: usize>`** — a single const-generic block accumulator replaces
  bc's *two* abstract base classes: `GeneralDigest` (64-byte block) and `LongDigest`
  (128-byte block). Rust models "shared buffering + per-algorithm compression" as
  *has-a*, not *is-a*: each digest embeds an `MdBuffer<N>` and supplies its
  compression step as a closure (state passed explicitly + struct-field destructuring
  to satisfy the borrow checker). The length field (width **and** endianness) is
  caller-encoded, so one buffer serves both big-endian (SHA) and little-endian
  (MD5/RIPEMD) families.
- **bc utilities dissolve into `core` primitives** — nothing to port:
  `Integers.RotateLeft` → `u32::rotate_left`, `Pack.UInt32_To_LE` / `LE_To_UInt32`
  → `to_le_bytes` / `from_le_bytes` (and `_BE` variants), `BitOperations.*` →
  `count_ones` / `leading_zeros` / …, `IMemoable` → `Clone` (`Copy()` → `clone`,
  `Reset(other)` → `clone_from`).
- **RIPEMD family shares `ripemd_common`** — the message-order / rotation tables and
  the five boolean functions live in one module; each variant supplies its own IV,
  round constants, register count, and combine. The compression uses value-rotation
  (like the reference) rather than bc's unrolled register-naming; for the 5-register
  variants the round-boundary register swaps land on shifted slots (16 mod 5 = 1),
  derived in `ripemd320.rs`.
- **XOF interface (`IXof`) is deferred** until the first extendable-output algorithm
  (SHAKE) is ported — it will be added to `tc_crypto_core` as `TryXof` / `Xof` then.
- **BLAKE2 backend dispatch** — the portable compression functions are always
  available. With `std` on x86/x86-64, BLAKE2b selects AVX2 and BLAKE2s selects
  SSE2 at runtime when supported; `no_std` and other architectures use the
  portable paths.

## Ported so far

| Algorithm | Spec | Block / length | Status |
|-----------|------|----------------|--------|
| **BLAKE2b** | RFC 7693 | 128-byte block, 64-bit words, 12 rounds | ✅ keyed/unkeyed + portable/AVX2 verified |
| **BLAKE2s** | RFC 7693 | 64-byte block, 32-bit words, 10 rounds | ✅ keyed/unkeyed + portable/SSE2 verified |
| **MD2** | RFC 1319 | standalone (16-byte, S-box) | ✅ RFC vectors verified |
| **MD4** | RFC 1320 | `MdBuffer<64>`, LE | ✅ RFC vectors verified |
| **MD5** | RFC 1321 | `MdBuffer<64>`, LE | ✅ RFC vectors verified |
| **SHA-1** | FIPS 180 | `MdBuffer<64>`, BE | ✅ known vectors verified |
| **SHA-224** | FIPS 180-2 | `MdBuffer<64>`, BE (reuses SHA-256 core) | ✅ known vectors verified |
| **SHA-256** | FIPS 180-2 | `MdBuffer<64>`, BE | ✅ known vectors verified |
| **SHA-3** | FIPS 202 | Keccak-f[1600] sponge, domain `0x06` | ✅ 224/256/384/512 vectors verified |
| **SHA-384** | FIPS 180-2 | `MdBuffer<128>`, BE (reuses SHA-512 core) | ✅ known vectors verified |
| **SHA-512** | FIPS 180-2 | `MdBuffer<128>`, BE | ✅ known vectors verified |
| **SHA-512/t** | FIPS 180-4 | `MdBuffer<128>`, BE, per-`t` IV + truncation | ✅ SHA-512/224 & /256 NIST vectors |
| **SM3** | GB/T 32905 | `MdBuffer<64>`, BE, 64 rounds | ✅ standard + BC long vectors |
| **RIPEMD-128** | — | `MdBuffer<64>`, LE, dual line | ✅ known vectors |
| **RIPEMD-160** | — | `MdBuffer<64>`, LE, dual line | ✅ known vectors |
| **RIPEMD-256** | — | `MdBuffer<64>`, LE, two lines + swaps | ✅ known vectors |
| **RIPEMD-320** | — | `MdBuffer<64>`, LE, two lines + swaps | ✅ known vectors |
| **Tiger** | — | `MdBuffer<64>`, LE, `0x01` pad, 3 passes | ✅ BC vectors + 64 KiB test |
| **Whirlpool** | ISO/IEC 10118-3 | `MdBuffer<64>`, BE, 256-bit length | ✅ ISO/BC vectors + million-`a` test |
| **DSTU 7564** | DSTU 7564:2014 | 512/1024-bit state, P/Q permutations | ✅ 256/384/512 + padding vectors |
| **GOST 34.11-2012** | GOST R 34.11-2012 | 512-bit state, S/P/L transformation | ✅ 256/512 BC vectors |
| **ISAP Hash** | NIST LWC | 320-bit state, 64-bit rate, 12-round permutation | ✅ official KAT + chunking vectors |
| **Keccak** | — | sponge (raw Keccak, domain pad `0x01`) | ✅ Keccak-256/512 vectors |
| **Xoodyak Hash** | NIST LWC | Cyclist over 384-bit Xoodoo, 128-bit rate | ✅ official KAT + chunking vectors |
| **NULL** | — | pass-through (buffers input, needs `alloc`) | ✅ |

## bc digest catalog (porting roadmap)

Line counts are the bc-csharp source sizes. ✅ = ported, ⬜ = pending,
⏸ = deferred until a prerequisite is available.

### Base / infrastructure

| bc file | Lines | Maps to |
|---------|------:|---------|
| `GeneralDigest` | 183 | ✅ `MdBuffer<64>` (composition) |
| `LongDigest` | 412 | ✅ `MdBuffer<128>` (composition) |
| `KeccakDigest` | 636 | ✅ sponge base (raw Keccak/SHA-3) |
| `NullDigest` | 86 | ✅ pass-through (needs `alloc`) |
| `NonMemoableDigest` | 76 | ⊘ intentionally skipped (see note) |
| `ShortenedDigest` | 104 | ⬜ truncating wrapper |

> **`NonMemoableDigest` — intentionally not ported.** In bc it wraps a digest to hide
> its `IMemoable` (snapshot/restore) capability, so a caller cannot clone the
> mid-computation state. Since `IMemoable` maps to Rust's `Clone`, "removing it" is
> just *not* implementing `Clone`. Rust achieves the same capability erasure natively:
> hand out `&mut dyn Digest` (the `Digest` trait has no `Clone`, and `dyn` erases the
> concrete type) or simply don't derive `Clone`. A forwarding newtype that omits
> `Clone` would reproduce it exactly, but it is redundant here, so it is skipped until
> an actual need appears.

### MD family (32-bit words, little-endian)

| Algorithm | Lines | Status |
|-----------|------:|--------|
| MD2 | 326 | ✅ |
| MD4 | 293 | ✅ |
| MD5 | 326 | ✅ |

### SHA-1 / SHA-2 (big-endian)

| Algorithm | Lines | Block | Status |
|-----------|------:|-------|--------|
| SHA-1 | 310 | `MdBuffer<64>` | ✅ |
| SHA-224 | 315 | `MdBuffer<64>` | ✅ (reuses SHA-256 core) |
| SHA-256 | 342 | `MdBuffer<64>` | ✅ |
| SHA-384 | 118 | `MdBuffer<128>` | ✅ (reuses SHA-512 core) |
| SHA-512 | 120 | `MdBuffer<128>` | ✅ ⭐ Ed25519 dependency ready |
| SHA-512/t | 245 | `MdBuffer<128>` | ✅ per-`t` IV generation + truncation |

### SHA-3 / Keccak (sponge; some are XOFs → need `IXof`)

| Algorithm | Lines | Status |
|-----------|------:|--------|
| SHA3 | 236 | ✅ 224/256/384/512 |
| SHAKE | 168 | ⬜ (XOF) |
| cSHAKE | 127 | ⬜ (XOF) |

### RIPEMD family (little-endian)

| Algorithm | Lines | Status |
|-----------|------:|--------|
| RIPEMD-128 | 495 | ✅ dual line, 4 rounds |
| RIPEMD-160 | 457 | ✅ dual line, 5 rounds |
| RIPEMD-256 | 448 | ✅ two lines + per-round swap |
| RIPEMD-320 | 479 | ✅ two lines + per-round swap |

### Other classic

| Algorithm | Lines | Status |
|-----------|------:|--------|
| Tiger | 928 | ✅ 192-bit, BC vectors + 64 KiB test |
| Whirlpool | 382 | ✅ ISO/BC vectors + million-`a` test |
| SM3 (China GB) | 340 | ✅ standard + BC long vectors |
| GOST3411 (1994) | 392 | ⏸ requires block-cipher abstraction + `Gost28147Engine` |
| GOST3411-2012 (Streebog) | 1089 (+256/512: 66/43) | ✅ shared core + 256/512 variants |
| DSTU7564 (Kupyna, Ukraine) | 627 | ✅ 256/384/512 + padding vectors |

> **GOST3411 (1994) is deferred.** Its bc-csharp implementation uses
> `IBlockCipher` with `Gost28147Engine` (256-bit key, 64-bit block, D-A S-box).
> The block-cipher layer and GOST 28147 engine will be ported first rather than
> embedding a digest-only copy of the cipher primitive.

### BLAKE family

| Algorithm | Lines | Status |
|-----------|------:|--------|
| BLAKE2b | 663 | ✅ keyed/unkeyed, variable output, portable + AVX2 |
| BLAKE2s | 688 | ✅ keyed/unkeyed, variable output, portable + SSE2 |
| BLAKE2xs | 387 | ⬜ (XOF) |
| BLAKE3 | 1029 | ⬜ (XOF) |

### Lightweight (NIST LWC) & special-purpose

| Algorithm | Lines | Status |
|-----------|------:|--------|
| Ascon | 273 (+ Hash256/Xof/Xof128/CXof128) | ⬜ |
| ISAP | 204 | ✅ 256-bit hash, official NIST LWC KAT vectors |
| PhotonBeetle | 369 | ⬜ |
| Sparkle | 298 | ⬜ |
| Xoodyak | 313 | ✅ 256-bit hash, official NIST LWC KAT vectors |
| Haraka-256 / -512 | 213 / 289 | ⬜ short-input |
| Skein | 125 (+ SkeinEngine) | ⬜ |
| ParallelHash / TupleHash | — | ⬜ (XOF combinators) |

## Build & test

```bash
# default std build (runtime SIMD dispatch on supported x86/x86-64)
cargo test -p tc_digest

# portable tests and the real no_std build
cargo test -p tc_digest --no-default-features
cargo build -p tc_digest --no-default-features

# BLAKE2b throughput: std runtime dispatch vs no_std portable
cargo bench -p tc_digest --bench blake2b
cargo bench -p tc_digest --bench blake2b --no-default-features

# BLAKE2s throughput: std runtime dispatch vs no_std portable
cargo bench -p tc_digest --bench blake2s
cargo bench -p tc_digest --bench blake2s --no-default-features
```

The BLAKE2 Criterion benchmarks cover keyed and unkeyed hashing at 64 B,
128 B, 1 KiB, 64 KiB, and 1 MiB. Benchmark names report the active backend,
including `avx2`, `sse2`, `std-portable`, or `no_std-portable`.

> no_std note: the crate uses
> `#![cfg_attr(not(any(test, feature = "std")), no_std)]`; test modules import
> `String` / `Vec` / `format!` explicitly from `alloc` so rust-analyzer doesn't
> flag them under its no_std view.
