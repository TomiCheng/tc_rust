# tc_digest

## 1. Overview

`tc_digest` provides message-digest and extendable-output function (XOF)
implementations ported from the Bouncy Castle C# digest package. It is a learning
project built around the traits defined by [`tc_crypto_core`](../tc_crypto_core):

- `TryDigest` is the fallible streaming digest interface.
- `Digest` is the infallible convenience interface.
- `TryXof` extends `TryDigest` with variable-length output.
- `Xof` is the infallible XOF convenience interface.

Most algorithms are streaming: call `update` one or more times, then finalize
into a caller-provided output buffer. Successful finalization resets the object
so it can be reused. XOFs can instead squeeze as much output as the caller needs.

The crate depends on `tc_crypto_core`, not `tc_math`. Its default `std` feature
enables runtime CPU-feature detection; disabling default features builds the
same algorithms for `no_std + alloc` with portable backends.

> This crate is a learning port and has not received an independent security
> audit. Do not treat it as a drop-in replacement for an audited cryptographic
> library.

## 2. Quick examples

### Fixed-output digest

Import `Digest` to use the infallible `update`, `do_final`, and `reset` methods:

```rust
use tc_crypto_core::Digest;
use tc_digest::Sha256Digest;

let mut digest = Sha256Digest::new();
digest.update(b"hello ");
digest.update(b"world");

let mut output = [0u8; 32];
let written = digest.do_final(&mut output);
assert_eq!(written, output.len());

// do_final resets the digest, so it is ready for another message.
digest.update(b"another message");
digest.do_final(&mut output);
```

Algorithms whose input contract can fail, notably `Prehash`, `Haraka256Digest`,
and `Haraka512Digest`, expose `TryDigest` methods returning `Result` instead of
the infallible `Digest` methods.

### Extendable-output function

Import both `Digest` for absorption and `Xof` for squeezing. Repeated `output`
calls continue the same output stream; `output_final` produces the requested
bytes and then resets the XOF:

```rust
use tc_crypto_core::{Digest, Xof};
use tc_digest::ShakeDigest;

let mut xof = ShakeDigest::new(128);
xof.update(b"message");

let mut first = [0u8; 32];
let mut second = [0u8; 68];
xof.output(&mut first);
xof.output_final(&mut second);

// first followed by second is the first 100 bytes of SHAKE128("message").
// output_final reset the XOF, so a new message can now be absorbed.
xof.update(b"next message");
```

Calling the ordinary `Digest::do_final` on an XOF remains supported and returns
that algorithm's default fixed output length.

## 3. Implemented algorithms

There are currently 42 exported algorithm and wrapper types.

### Fixed-output digests and wrappers

| Family | Public types and variants | Notes |
|--------|---------------------------|-------|
| MD | `Md2Digest`, `Md4Digest`, `Md5Digest` | RFC known-answer vectors |
| SHA-1 / SHA-2 | `Sha1Digest`, `Sha224Digest`, `Sha256Digest`, `Sha384Digest`, `Sha512Digest`, `Sha512tDigest` | SHA-512/224 and SHA-512/256 supported through SHA-512/t |
| SHA-3 / Keccak | `Sha3Digest`, `KeccakDigest` | SHA3-224/256/384/512; raw Keccak-128/224/256/288/384/512 |
| RIPEMD | `RipeMD128Digest`, `RipeMD160Digest`, `RipeMD256Digest`, `RipeMD320Digest` | All four Bouncy Castle variants |
| BLAKE | `Blake2bDigest`, `Blake2sDigest`, `Blake3Digest` | Keyed and variable-output BLAKE2 modes; BLAKE3 also implements `Xof` |
| Ascon | `AsconHash256` | Current NIST SP 800-232 hash |
| Ascon legacy | `AsconDigest`, `AsconParameters` | Deprecated Ascon v1.2 Hash / HashA compatibility API |
| GOST / DSTU | `Gost3411_2012_256Digest`, `Gost3411_2012_512Digest`, `Dstu7564Digest` | Streebog-256/512 and DSTU 7564-256/384/512 |
| Other classic hashes | `Sm3Digest`, `TigerDigest`, `WhirlpoolDigest` | Standard and Bouncy Castle vectors |
| Lightweight hashes | `IsapDigest`, `PhotonBeetleDigest`, `XoodyakDigest` | NIST LWC known-answer vectors |
| Haraka | `Haraka256Digest`, `Haraka512Digest` | Fixed 32/64-byte input, 32-byte output; fallible input contract |
| Wrappers | `ShortenedDigest<D>`, `Prehash`, `NullDigest` | Truncation, fixed-length prehash pass-through, and arbitrary pass-through |

### XOFs and variable-length constructions

| Family | Public types and variants | Notes |
|--------|---------------------------|-------|
| SHAKE | `ShakeDigest` | SHAKE128 and SHAKE256 |
| cSHAKE | `CShakeDigest` | cSHAKE128 and cSHAKE256 with function-name/customization strings |
| BLAKE | `Blake2xsDigest`, `Blake3Digest` | BLAKE2xs and BLAKE3 streaming output |
| Ascon | `AsconXof128`, `AsconCXof128` | NIST SP 800-232 XOF and customizable XOF |
| Ascon legacy | `AsconXof`, `AsconXofParameters` | Deprecated Ascon v1.2 Xof / XofA compatibility API |
| SP 800-185 | `TupleHash`, `ParallelHash` | 128-bit and 256-bit security variants; fixed and XOF modes |

The implementation is validated with specification vectors, Bouncy Castle
vectors, official KAT files, streaming/chunking checks, reset/clone tests, and
portable-versus-accelerated backend comparisons where applicable.

## 4. Not yet implemented

Relative to the current Bouncy Castle C# digest directory, these algorithm
families remain deferred:

| Algorithm | Reason |
|-----------|--------|
| `SparkleDigest` (ESCH-256 / ESCH-384) | Requires the SPARKLE permutation currently supplied by Bouncy Castle's `SparkleEngine`. The shared primitive should live below the future digest and cipher crates rather than be duplicated here. |
| `GOST3411Digest` (GOST 34.11-94) | Requires the future block-cipher abstraction and `Gost28147Engine`. |
| `SkeinDigest` / `SkeinEngine` | Requires the Threefish tweakable block cipher. |

`NonMemoableDigest` is intentionally omitted. Bouncy Castle uses it to hide
snapshot/copy support; Rust can erase that capability by exposing a digest
through a trait object that does not include `Clone`, so a dedicated forwarding
wrapper is unnecessary.

## 5. Building and testing

### Default `std` build

The default feature set enables `std`. On x86 and x86-64, the crate detects CPU
features at runtime and selects these accelerated backends when available:

- BLAKE2b: AVX2
- BLAKE2s: SSE2
- Haraka-256/512: AES-NI

All other targets and unsupported CPUs automatically use the portable paths.

```bash
cargo build -p tc_digest
cargo test -p tc_digest
```

### `no_std + alloc` build

Disable default features to remove the `std` dependency and runtime CPU-feature
detection. This selects the portable implementations. Digest results are
identical to the `std` build.

```bash
# This is the real no_std compilation check.
cargo build -p tc_digest --no-default-features

# Runs the portable configuration, but the Rust test harness itself still uses std.
cargo test -p tc_digest --no-default-features
```

The crate declares `alloc` because dynamic constructions such as `NullDigest`,
`Prehash`, `ShortenedDigest`, cSHAKE, BLAKE3, TupleHash, and ParallelHash need
owned buffers or names. Many fixed-state digests remain allocation-free, but a
final `no_std` application must provide an allocator when it uses allocating
algorithms.

A consumer selects the portable configuration with:

```toml
[dependencies]
tc_crypto_core = { path = "../tc_crypto_core" }
tc_digest = { path = "../tc_digest", default-features = false }
```

### Additional validation

```bash
# Entire workspace, including doctests.
cargo test --workspace

# Lints for both configurations.
cargo clippy -p tc_digest --all-targets
cargo clippy -p tc_digest --all-targets --no-default-features

# Build the crate documentation.
cargo doc -p tc_digest --no-deps

# Full PHOTON-Beetle KAT; intentionally ignored in normal debug tests.
cargo test -p tc_digest --release --test photon_beetle_kat -- --ignored

# BLAKE2 throughput benchmarks.
cargo bench -p tc_digest --bench blake2b
cargo bench -p tc_digest --bench blake2s
cargo bench -p tc_digest --bench blake2b --no-default-features
cargo bench -p tc_digest --bench blake2s --no-default-features
```
