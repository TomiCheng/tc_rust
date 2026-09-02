# tc_rust

`tc_rust` is a pure-Rust cryptography workspace ported from the
[Bouncy Castle C#](https://github.com/bcgit/bc-csharp) library. It is a personal
learning project for studying Rust, cryptographic algorithms, and API design.

> [!WARNING]
> This is an independent, unofficial reimplementation. It is not affiliated
> with or endorsed by the Legion of the Bouncy Castle Inc. The workspace is
> still under development, its APIs are unstable, and it has not been audited.
> **Do not use it in production or for real-world security.**

## Current status

The low-level block-cipher and stream-cipher engine inventories are implemented.
Digest support is close to the current target, while key wrapping and the
higher-level elliptic-curve work still have known gaps.

| Area | Current progress | Remaining work |
| --- | --- | --- |
| Block ciphers | 28 public engines with known-answer tests | The current raw-engine inventory is complete |
| Stream ciphers | 11 engines; the current inventory is complete | Higher-level protocols and authenticated encryption are outside this crate |
| Block modes | 8 mode families | Padding, buffering, and ciphertext stealing are not provided |
| Digests and XOFs | 42 exported digest, XOF, and wrapper types | GOST 34.11-94, Skein, and Sparkle |
| Key wrapping | RFC 3394, RFC 5649, and DSTU 7624 | RFC 3211, DESede, and RC2 wrappers |
| Mathematics | Big integers, binary-polynomial and raw arithmetic, prime-field support, X25519, and 33 named SEC curves | General constant-time EC scalar multiplication, projective/WNAF paths, and the remaining X25519 helpers |

The prerequisites for GOST 34.11-94 and Skein are now present in the workspace.
Sparkle digest support still requires a shared Sparkle permutation/engine.

## Workspace crates

| Crate | Purpose | Runtime support |
| --- | --- | --- |
| [`tc_cipher_core`](crates/tc_cipher_core) | Shared block-cipher, stream-cipher, and key-wrapping operation/initialization traits | Core-only `no_std` |
| [`tc_crypto_core`](crates/tc_crypto_core) | Shared `TryDigest` / `Digest`, `TryXof` / `Xof`, and key-wrapper traits | Core-only `no_std`; `alloc` is optional for `Wrapper` |
| [`tc_block_cipher`](crates/tc_block_cipher) | Block cipher engines and their validated parameter types | Core-only subset, full `no_std + alloc`, or `std` with AES-NI detection |
| [`tc_stream_cipher`](crates/tc_stream_cipher) | Stream cipher engines and shared error handling | Core-only `no_std` |
| [`tc_block_modes`](crates/tc_block_modes) | Generic block cipher modes built on `tc_cipher_core` | `no_std + alloc` |
| [`tc_digest`](crates/tc_digest) | Message digests, XOFs, and digest wrappers | `no_std + alloc`; `std` enables runtime CPU-feature detection |
| [`tc_math`](math/tc_math) | Arbitrary-precision integers, finite-field arithmetic, and elliptic-curve foundations | `no_std + alloc`; `std` adds lazy caching |

The core trait crates do not depend on algorithm implementations. Concrete
algorithm crates depend on the appropriate core crate, which keeps the
dependency graph acyclic and lets applications select only the layers they use.

## Implemented algorithms

### Block ciphers

- AES (portable T-table, light, and AES-NI dispatch), ARIA, Blowfish
- Camellia and Camellia Light, CAST5, CAST6
- DES, Triple DES, DSTU 7624, GOST 28147-89
- IDEA, Noekeon, RC2, RC5-32, RC5-64, RC6, Rijndael
- SEED, Serpent, Tnepres, Skipjack, SM4
- TEA, XTEA, Threefish, and Twofish

### Stream ciphers

- RC4, HC-128, HC-256, and ISAAC
- Salsa20 and XSalsa20
- ChaCha, ChaCha7539, and XChaCha20
- VMPC and VMPC-KSA3

Several of these algorithms are retained for compatibility and study only and
are not suitable for new designs.

### Block cipher modes

- ECB and CBC
- CFB and OpenPGP CFB
- OFB
- CTR/SIC
- GCTR/GOFB
- KCTR

Modes operate on blocks or byte streams as defined by their traits. They do not
add padding, authentication, or message framing.

### Digests and XOFs

- MD2, MD4, MD5
- SHA-1, SHA-224/256/384/512, SHA-512/t
- SHA-3, Keccak, SHAKE, and cSHAKE
- RIPEMD-128/160/256/320
- BLAKE2b, BLAKE2s, BLAKE2xs, and BLAKE3
- Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128, and legacy Ascon v1.2 variants
- GOST 34.11-2012, DSTU 7564, SM3, Tiger, and Whirlpool
- ISAP Hash, Photon-Beetle Hash, Xoodyak Hash, and Haraka-256/512
- TupleHash, ParallelHash, `ShortenedDigest`, `Prehash`, and `NullDigest`

See the [`tc_digest` roadmap](crates/tc_digest/README.md) for variant-level
details and usage examples.

### Key wrapping

- Generic RFC 3394 wrapping, with AES, ARIA, Camellia, and SEED aliases
- Generic RFC 5649 wrapping with padding, with AES and ARIA aliases
- DSTU 7624 key wrapping

### Mathematics

- Signed arbitrary-precision `BigInteger`
- Arithmetic, bitwise operations, shifts, conversions, and arbitrary-radix text
- GCD, modular inverse, modular exponentiation, and probable-prime operations
- Binary-polynomial, raw natural-number, and elliptic-curve field arithmetic
- X25519 scalar multiplication and 33 named SEC curves

Except for the X25519 ladder, the general `tc_math` arithmetic is not promised
to be constant-time.

## Feature model

The workspace uses three runtime levels:

| Level | Meaning |
| --- | --- |
| Core-only `no_std` | No allocator and no standard library. Used by the trait crates, stream ciphers, and the core-only block-cipher subset. |
| `no_std + alloc` | No standard library, but owned buffers and dynamically sized state are available. Required by digests, modes, wrappers, math, and some block ciphers. |
| `std` | The default where offered. It preserves the same algorithms and adds conveniences such as lazy caches or runtime CPU-feature detection. |

Notable `std` acceleration currently includes AES-NI for AES, AVX2 for BLAKE2b,
SSE2 for BLAKE2s, and AES-NI for Haraka. Portable implementations remain
available when `std` is disabled.

## Building and testing

The workspace targets stable Rust with the 2024 edition.

```bash
# Build and test the complete workspace with default features
cargo build --workspace --locked
cargo test --workspace --locked

# Lint and generate documentation
cargo clippy --workspace --all-targets --locked
cargo doc --workspace --no-deps --locked
```

Representative `no_std` builds:

```bash
# Core-only crates
cargo build -p tc_cipher_core --locked
cargo build -p tc_crypto_core --no-default-features --locked
cargo build -p tc_stream_cipher --locked

# Core-only block-cipher subset
cargo build -p tc_block_cipher --no-default-features --locked

# Full block-cipher inventory without std
cargo build -p tc_block_cipher --no-default-features --features alloc --locked

# Crates that require alloc but not std
cargo build -p tc_block_modes --locked
cargo build -p tc_digest --no-default-features --locked
cargo build -p tc_math --no-default-features --locked
```

`cargo test` always uses Rust's standard-library test harness. Use `cargo build`
with the feature combinations above to verify the library's actual `no_std`
configuration.

Benchmarks are available in the algorithm crates:

```bash
cargo bench -p tc_block_cipher
cargo bench -p tc_digest
cargo bench -p tc_math
```

## Reference and license

Algorithm behavior and test vectors are compared with the
[Bouncy Castle C# source](https://github.com/bcgit/bc-csharp). This attribution
does not imply compatibility certification or endorsement.

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option (SPDX: `MIT OR Apache-2.0`).
