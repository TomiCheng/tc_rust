# tc_digest

Message-digest (hash) algorithms, ported from the Bouncy Castle C# library
(`bc-csharp`, `crypto/digests/`) as a **learning project**.

Each algorithm implements the `TryDigest` / `Digest` traits from
[`tc_crypto_core`](../tc_crypto_core). Digests are pure fixed-size bit/byte
computation, so this crate is `no_std` and needs no `alloc`; it depends **only** on
`tc_crypto_core` — never on `tc_math` (hashes carry no big-integer arithmetic).

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
- **XOF interface (`IXof`) is deferred** until the first extendable-output algorithm
  (SHAKE) is ported — it will be added to `tc_crypto_core` as `TryXof` / `Xof` then.

## Ported so far

| Algorithm | Spec | Block / length | Status |
|-----------|------|----------------|--------|
| **MD2** | RFC 1319 | standalone (16-byte, S-box) | ✅ RFC vectors verified |
| **MD4** | RFC 1320 | `MdBuffer<64>`, LE | ✅ RFC vectors verified |
| **MD5** | RFC 1321 | `MdBuffer<64>`, LE | ✅ RFC vectors verified |
| **SHA-1** | FIPS 180 | `MdBuffer<64>`, BE | ✅ known vectors verified |
| **SHA-224** | FIPS 180-2 | `MdBuffer<64>`, BE (reuses SHA-256 core) | ✅ known vectors verified |
| **SHA-256** | FIPS 180-2 | `MdBuffer<64>`, BE | ✅ known vectors verified |

## bc digest catalog (porting roadmap)

Line counts are the bc-csharp source sizes. ✅ = ported, ⬜ = pending.

### Base / infrastructure

| bc file | Lines | Maps to |
|---------|------:|---------|
| `GeneralDigest` | 183 | ✅ `MdBuffer<64>` (composition) |
| `LongDigest` | 412 | ✅ `MdBuffer<128>` (composition) |
| `KeccakDigest` | 636 | ⬜ sponge base (SHA-3/SHAKE) |
| `NullDigest` | 86 | ⬜ no-op wrapper |
| `NonMemoableDigest` | 76 | ⬜ wrapper (blocks `Clone`) |
| `ShortenedDigest` | 104 | ⬜ truncating wrapper |

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
| SHA-384 | 118 | `MdBuffer<128>` | ⬜ |
| SHA-512 | 120 | `MdBuffer<128>` | ⬜ ⭐ Ed25519 dependency |
| SHA-512/t | 245 | `MdBuffer<128>` | ⬜ truncated variant |

### SHA-3 / Keccak (sponge; some are XOFs → need `IXof`)

| Algorithm | Lines | Status |
|-----------|------:|--------|
| SHA3 | 236 | ⬜ |
| SHAKE | 168 | ⬜ (XOF) |
| cSHAKE | 127 | ⬜ (XOF) |

### RIPEMD family (little-endian)

| Algorithm | Lines | Status |
|-----------|------:|--------|
| RIPEMD-128 | 495 | ⬜ |
| RIPEMD-160 | 457 | ⬜ |
| RIPEMD-256 | 448 | ⬜ |
| RIPEMD-320 | 479 | ⬜ |

### Other classic

| Algorithm | Lines | Status |
|-----------|------:|--------|
| Tiger | 928 | ⬜ |
| Whirlpool | 382 | ⬜ |
| SM3 (China GB) | 340 | ⬜ |
| GOST3411 (1994) | 392 | ⬜ |
| GOST3411-2012 (Streebog) | 1089 (+256/512: 66/43) | ⬜ |
| DSTU7564 (Kupyna, Ukraine) | 627 | ⬜ |

### BLAKE family

| Algorithm | Lines | Status |
|-----------|------:|--------|
| BLAKE2b | 663 | ⬜ |
| BLAKE2s | 688 | ⬜ |
| BLAKE2xs | 387 | ⬜ (XOF) |
| BLAKE3 | 1029 | ⬜ (XOF) |

### Lightweight (NIST LWC) & special-purpose

| Algorithm | Lines | Status |
|-----------|------:|--------|
| Ascon | 273 (+ Hash256/Xof/Xof128/CXof128) | ⬜ |
| ISAP | 204 | ⬜ |
| PhotonBeetle | 369 | ⬜ |
| Sparkle | 298 | ⬜ |
| Xoodyak | 313 | ⬜ |
| Haraka-256 / -512 | 213 / 289 | ⬜ short-input |
| Skein | 125 (+ SkeinEngine) | ⬜ |
| ParallelHash / TupleHash | — | ⬜ (XOF combinators) |

## Build & test

```bash
# tests (includes RFC test vectors)
cargo test -p tc_digest

# no_std build (the real no_std check — cargo test links std for the harness)
cargo build -p tc_digest
```

> no_std note: the crate is `#![cfg_attr(not(test), no_std)]`; test modules import
> `String` / `Vec` / `format!` explicitly from `alloc` (with `#[cfg(test)] extern
> crate alloc`) so rust-analyzer doesn't flag them under its no_std view.
