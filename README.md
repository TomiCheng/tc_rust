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
Digest support has reached the current target, while key wrapping and the
higher-level elliptic-curve work still have known gaps.

| Area | Current progress | Remaining work |
| --- | --- | --- |
| Block ciphers | 28 public engines with known-answer tests | The current raw-engine inventory is complete |
| Stream ciphers | 11 engines; the current inventory is complete | Higher-level protocols and authenticated encryption are outside this crate |
| Block modes | 8 mode families | Padding, buffering, and ciphertext stealing are not provided |
| Digests and XOFs | 45 exported digest, XOF, and wrapper types | The current Bouncy Castle digest inventory is complete |
| Key wrapping | RFC 3394, RFC 5649, and DSTU 7624 | RFC 3211, DESede, and RC2 wrappers |
| Mathematics | Big integers, binary-polynomial and raw arithmetic, prime-field support, X25519, and 33 named SEC curves | General constant-time EC scalar multiplication, projective/WNAF paths, and the remaining X25519 helpers |

GOST 34.11-94 and Skein 1.3 reuse the workspace's GOST 28147 and Threefish
engines respectively; both provide streaming, clone, and reset behavior.

## Workspace crates

| Crate | Purpose | Runtime support |
| --- | --- | --- |
| [`tc_crypto`](crypto/tc_crypto) | Shared algorithm metadata contracts | Core-only `no_std` |
| [`tc_cipher`](crypto/tc_cipher) | Shared cipher, mode, and key-wrapping traits and errors | Core-only `no_std` |
| [`tc_params`](crypto/tc_params) | Shared object-safe cryptographic parameter traits and convenience types | Core-only `no_std` |
| [`tc_macs`](crypto/tc_macs) | Shared message-authentication-code traits and errors | Core-only `no_std` |
| [Block-cipher family crates](crypto/block_cipher) | Independent block-cipher implementations built on `tc_cipher` and `tc_params` | Core-only `no_std`; AES can select AES-NI at runtime |
| [`tc_chacha`](crypto/stream_cipher/tc_chacha), [`tc_hc`](crypto/stream_cipher/tc_hc), [`tc_isaac`](crypto/stream_cipher/tc_isaac), [`tc_rc4`](crypto/stream_cipher/tc_rc4), [`tc_salsa20`](crypto/stream_cipher/tc_salsa20), [`tc_vmpc`](crypto/stream_cipher/tc_vmpc) | Independent stream-cipher implementation crates built on `tc_cipher` | Core-only `no_std` |
| [`tc_ecb`](crypto/block_modes/tc_ecb), [`tc_cbc`](crypto/block_modes/tc_cbc), [`tc_cfb`](crypto/block_modes/tc_cfb), [`tc_ofb`](crypto/block_modes/tc_ofb), [`tc_ctr`](crypto/block_modes/tc_ctr) | Independent ECB, CBC, CFB/OpenPGP CFB, OFB/GCTR, and CTR/KCTR crates built on `tc_cipher` | Core-only `no_std`; `alloc` enables runtime-sized variants where needed |
| [`tc_digest`](crypto/tc_digest) | Shared message-digest and XOF traits | Core-only `no_std` |
| [Digest family crates](crypto/digest) | Independent message-digest, XOF, and digest-adapter implementations | `no_std`; allocation and optional CPU acceleration vary by family |
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

See the [digest crate guide](crypto/digest/README.md) for variant-level
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
cargo build -p tc_crypto -p tc_cipher -p tc_params -p tc_digest -p tc_macs --locked
cargo build -p tc_chacha -p tc_hc -p tc_isaac -p tc_rc4 -p tc_salsa20 -p tc_vmpc --locked

# Representative block-cipher crate (all family crates are no_std)
cargo build -p tc_aes --locked

# Block modes without alloc (fixed-size variants)
cargo build -p tc_ecb --locked
cargo build -p tc_cbc -p tc_cfb -p tc_ofb -p tc_ctr --no-default-features --locked

# Runtime-sized block-mode variants (alloc, but not std)
cargo build -p tc_cbc -p tc_cfb -p tc_ofb -p tc_ctr --locked

# Portable digest backends without std
cargo build -p tc_blake2 -p tc_haraka --no-default-features --locked

# Other crates that require alloc but not std
cargo build -p tc_math --no-default-features --locked
```

`cargo test` always uses Rust's standard-library test harness. Use `cargo build`
with the feature combinations above to verify the library's actual `no_std`
configuration.

Benchmarks are available in the algorithm crates:

```bash
cargo bench -p tc_aes --bench aes
cargo bench -p tc_blake2
cargo bench -p tc_math
```

## Reference and license

Algorithm behavior and test vectors are compared with the
[Bouncy Castle C# source](https://github.com/bcgit/bc-csharp). This attribution
does not imply compatibility certification or endorsement.

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option (SPDX: `MIT OR Apache-2.0`).
