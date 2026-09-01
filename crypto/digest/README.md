# Message digests

## 1. Overview

The crates in this directory provide message-digest and extendable-output
function (XOF) implementations ported from the Bouncy Castle C# digest package.
The v1 implementation placed every algorithm in `crates/tc_digest`; v2 groups
related algorithms into focused crates and keeps the shared contracts in
[`tc_digest`](../tc_digest):

- `TryDigest` is the fallible streaming digest interface.
- `Digest` is the infallible convenience interface.
- `TryXof` extends `TryDigest` with variable-length output.
- `Xof` is the infallible XOF convenience interface.

Most algorithms are streaming: call `update` one or more times, then finalize
into a caller-provided output buffer. Successful finalization resets the object
so it can be reused. XOFs can instead squeeze as much output as the caller
needs.

Every implementation supports `no_std`. Crates that retain owned buffers or
runtime-generated names use `alloc`. The `std` features in `tc_blake2` and
`tc_haraka` enable runtime CPU-feature detection; disabling their default
features selects the portable backends.

The legacy sources remain under `crates/tc_digest` as migration references.
New code should depend on the focused v2 crates below.

> These crates are learning ports and have not received an independent
> security audit. Do not use them as replacements for audited cryptographic
> libraries.

## 2. Quick examples

### Fixed-output digest

Import `Digest` from the shared `tc_digest` crate and the algorithm from its
family crate:

```rust
use tc_digest::Digest;
use tc_sha::Sha256Digest;

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

Algorithms whose input contract can fail, notably `Prehash`,
`Haraka256Digest`, and `Haraka512Digest`, expose `TryDigest` methods returning
`Result` instead of the infallible `Digest` methods.

### Extendable-output function

Import `Digest` for absorption and `Xof` for squeezing. Repeated `output` calls
continue the same output stream; `output_final` produces the requested bytes
and then resets the XOF:

```rust
use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;

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

Calling `Digest::do_final` on an XOF remains supported and returns that
algorithm's default fixed output length.

## 3. Implemented algorithms

The v1 public algorithm and adapter types are available in the v2 family
crates.

### Fixed-output digests and adapters

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
| Lightweight hashes | `IsapDigest`, `PhotonBeetleDigest`, `SparkleDigest`, `XoodyakDigest` | NIST LWC known-answer vectors; `SparkleDigest` provides ESCH-256 and ESCH-384 |
| Haraka | `Haraka256Digest`, `Haraka512Digest` | Fixed 32/64-byte input, 32-byte output; fallible input contract |
| Adapters | `ShortenedDigest<D>`, `Prehash`, `NullDigest` | Truncation, fixed-length prehash pass-through, and arbitrary pass-through |

### XOFs and variable-length constructions

| Family | Public types and variants | Notes |
|--------|---------------------------|-------|
| SHAKE | `ShakeDigest` | SHAKE128 and SHAKE256 |
| cSHAKE | `CShakeDigest` | cSHAKE128 and cSHAKE256 with function-name/customization strings |
| BLAKE | `Blake2xsDigest`, `Blake3Digest` | BLAKE2xs and BLAKE3 streaming output |
| Ascon | `AsconXof128`, `AsconCXof128` | NIST SP 800-232 XOF and customizable XOF |
| Ascon legacy | `AsconXof`, `AsconXofParameters` | Deprecated Ascon v1.2 Xof / XofA compatibility API |
| SP 800-185 | `TupleHash`, `ParallelHash` | 128-bit and 256-bit security variants; fixed and XOF modes |

The implementations are validated with specification vectors, Bouncy Castle
vectors, official KAT files, streaming/chunking checks, reset/clone tests, and
portable-versus-accelerated backend comparisons where applicable.

## 4. Not yet implemented

Relative to the current Bouncy Castle C# digest directory, these algorithm
families remain deferred:

| Algorithm | Reason |
|-----------|--------|
| `GOST3411Digest` (GOST 34.11-94) | Requires the future block-cipher abstraction and `Gost28147Engine`. |
| `SkeinDigest` / `SkeinEngine` | Requires the Threefish tweakable block cipher. |

## 5. Features and allocation

On x86 and x86-64, the default `std` features select accelerated backends when
the CPU reports support:

- `tc_blake2`: AVX2 for BLAKE2b and SSE2 for BLAKE2s.
- `tc_haraka`: AES-NI for Haraka-256/512.

Disabling default features selects the portable implementations. Digest results
are identical in both configurations.

The crates containing `NullDigest`, `Prehash`, `ShortenedDigest`, cSHAKE,
BLAKE3, TupleHash, ParallelHash, or runtime-generated SHA-512/t names use
`alloc`. Fixed-state algorithms that do not retain dynamic data remain
allocation-free.

## 6. Dependencies

Applications depend on the shared traits and only the algorithm families they
use. Local development can specify both `version` and `path`:

```toml
[dependencies]
tc_digest = { version = "0.1", path = "crypto/tc_digest" }
tc_sha = { version = "0.1", path = "crypto/digest/tc_sha" }
tc_keccak = { version = "0.1", path = "crypto/digest/tc_keccak" }
```

## 7. Building and testing

Build or test one family independently:

```bash
cargo build -p tc_sha
cargo test -p tc_sha
```

Check the portable backends explicitly:

```bash
cargo build -p tc_blake2 --no-default-features
cargo test -p tc_blake2 --no-default-features
cargo build -p tc_haraka --no-default-features
```

Additional validation commands:

```bash
# Compile every workspace test target.
cargo test --workspace --no-run

# Lint an individual family.
cargo clippy -p tc_keccak --all-targets -- -D warnings

# Build the documentation.
cargo doc -p tc_keccak --no-deps

# Full PHOTON-Beetle KAT; intentionally ignored in normal debug tests.
cargo test -p tc_photon_beetle --release --test photon_beetle_kat -- --ignored

# BLAKE2 throughput benchmarks.
cargo bench -p tc_blake2 --bench blake2b
cargo bench -p tc_blake2 --bench blake2s
cargo bench -p tc_blake2 --bench blake2b --no-default-features
cargo bench -p tc_blake2 --bench blake2s --no-default-features
```
