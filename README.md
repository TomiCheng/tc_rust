# tc_rust

`tc_rust` is a pure-Rust cryptography workspace ported from the
[Bouncy Castle C#](https://github.com/bcgit/bc-csharp) library. It is a personal
learning project for studying Rust, cryptographic algorithms, and API design.

> [!WARNING]
> This is an independent, unofficial reimplementation. It is not affiliated
> with or endorsed by the Legion of the Bouncy Castle Inc. The workspace is
> still under development, its APIs are unstable, and it has not been audited.
> **Do not use it in production or for real-world security.**

This workspace is an incubator. When a crate matures, it moves to a repository
of its own and is published on crates.io; the incubator copy is then retired,
and the crates that remain here depend on the published version.

## Graduated repositories

### [tc_core](https://github.com/TomiCheng/tc_core)

- [`tc_constant_time`](https://crates.io/crates/tc_constant_time) — constant-time
  selection, comparison and conditional arithmetic primitives
- [`tc_runtime`](https://crates.io/crates/tc_runtime) — `no_std` CPU feature
  detection and capability proof tokens for x86 and AArch64
- [`tc_zeroize`](https://crates.io/crates/tc_zeroize) — explicit memory erasure
  with volatile writes and opt-in scope guards

### [tc_math](https://github.com/TomiCheng/tc_math)

- [`tc_bigint`](https://crates.io/crates/tc_bigint) — fixed-width, padded and
  arbitrary-precision big integers, constant time in the fixed-width and padded
  forms
- [`tc_modular`](https://crates.io/crates/tc_modular) — modular arithmetic and
  Montgomery forms over `tc_bigint`
- [`tc_prime`](https://crates.io/crates/tc_prime) — trial division,
  Miller-Rabin and Shawe-Taylor provable primes
- [`tc_binpoly`](https://crates.io/crates/tc_binpoly) — binary-polynomial
  arithmetic over GF(2^n), constant time with PCLMULQDQ
- [`tc_ec_core`](https://crates.io/crates/tc_ec_core) — curve, point and
  field-element traits; wNAF, GLV, τ-adic NAF and fixed-base comb
  multiplication
- [`tc_fp_curve`](https://crates.io/crates/tc_fp_curve) and
  [`tc_f2m_curve`](https://crates.io/crates/tc_f2m_curve) — generic prime- and
  binary-field curves, each as a constant-time and a variable-time set, with
  the SEC named curves
- [`tc_fp_custom`](https://crates.io/crates/tc_fp_custom) and
  [`tc_f2m_custom`](https://crates.io/crates/tc_f2m_custom) — the SEC and SM2
  curves with per-field specialized arithmetic

### [tc_asn1](https://github.com/TomiCheng/tc_asn1)

- [`tc_asn1`](https://crates.io/crates/tc_asn1) — BER, CER and DER codecs for
  the ASN.1 universal types
- [`tc_asn1_x500`](https://crates.io/crates/tc_asn1_x500) — X.501 names and
  X.520 attribute types

### [tc_digest](https://github.com/TomiCheng/tc_digest)

- [`tc_digest`](https://crates.io/crates/tc_digest) — streaming digest and XOF
  traits, fallible and infallible; with the `alloc` feature, the
  `NullDigest`, `Prehash` and `ShortenedDigest` adapters
- [`tc_md`](https://crates.io/crates/tc_md) — MD2, MD4 and MD5 for legacy
  interoperability
- [`tc_sha`](https://crates.io/crates/tc_sha) — SHA-1 and SHA-2, including
  SHA-512/t
- [`tc_keccak`](https://crates.io/crates/tc_keccak) — Keccak, SHA-3, SHAKE,
  cSHAKE, TupleHash and ParallelHash
- [`tc_blake`](https://crates.io/crates/tc_blake) — BLAKE2b, BLAKE2s,
  BLAKE2xs and BLAKE3, with AVX2 and SSE2 code for BLAKE2 and an optional
  backend on the `blake3` crate
- [`tc_ascon_hash`](https://crates.io/crates/tc_ascon_hash) — Ascon-Hash256,
  Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232); the Ascon v1.2 hashes
  and ISAP Hash with the `legacy` feature

### [tc_block_cipher](https://github.com/TomiCheng/tc_block_cipher)

- [`tc_block_cipher`](https://crates.io/crates/tc_block_cipher) — block-cipher
  traits, errors and wiping key containers
- [`tc_aes`](https://crates.io/crates/tc_aes) — AES with AES-NI, RustCrypto,
  table and small-footprint engines
- [`tc_aria`](https://crates.io/crates/tc_aria) — ARIA (RFC 5794)
- [`tc_camellia`](https://crates.io/crates/tc_camellia) — Camellia (RFC 3713)
- [`tc_des`](https://crates.io/crates/tc_des) — DES and Triple DES, with
  weak-key and parity helpers for key generation
- [`tc_dstu7624`](https://crates.io/crates/tc_dstu7624) — DSTU 7624:2014
  (Kalyna) with 128-, 256- and 512-bit blocks
- [`tc_rc_cipher`](https://crates.io/crates/tc_rc_cipher) — RC2, RC5 and RC6
- [`tc_sm4`](https://crates.io/crates/tc_sm4) — SM4 (GB/T 32907-2016)
- [`tc_threefish`](https://crates.io/crates/tc_threefish) — Threefish-256,
  Threefish-512 and Threefish-1024
- [`tc_gost28147`](https://crates.io/crates/tc_gost28147) — GOST 28147-89 with
  the standard and caller-supplied S-boxes
- [`tc_block_modes`](https://crates.io/crates/tc_block_modes) — ECB, CBC, CFB,
  OFB and CTR, and OpenPGP CFB, GOST 28147 GCTR (GOFB) and DSTU 7624 KCTR
- [`tc_block_padding`](https://crates.io/crates/tc_block_padding) — PKCS#7,
  ISO 7816-4, ANSI X9.23, TBC, zero-byte and ISO 10126 padding

### [tc_stream_cipher](https://github.com/TomiCheng/tc_stream_cipher)

- [`tc_stream_cipher`](https://crates.io/crates/tc_stream_cipher) —
  stream-cipher traits, errors and wiping key and IV containers
- [`tc_chacha`](https://crates.io/crates/tc_chacha) — ChaCha, ChaCha20
  (RFC 8439) and XChaCha20
- [`tc_salsa20`](https://crates.io/crates/tc_salsa20) — Salsa20 and XSalsa20
- [`tc_hc`](https://crates.io/crates/tc_hc) — HC-128 and HC-256
- [`tc_rc4_family`](https://crates.io/crates/tc_rc4_family) — RC4, VMPC,
  VMPC-KSA3 and ISAAC

### [tc_aead_cipher](https://github.com/TomiCheng/tc_aead_cipher)

- [`tc_aead_cipher`](https://crates.io/crates/tc_aead_cipher) — AEAD contracts
  and the GCM, GCM-SIV, CCM, KCCM, EAX and OCB modes over any block cipher
- [`tc_ascon_aead`](https://crates.io/crates/tc_ascon_aead) — Ascon-AEAD128
  and the Ascon v1.2 AEAD variants
- [`tc_chacha_aead`](https://crates.io/crates/tc_chacha_aead) —
  ChaCha20-Poly1305 and XChaCha20-Poly1305
- [`tc_grain128_aead`](https://crates.io/crates/tc_grain128_aead) —
  Grain-128AEAD
- [`tc_sparkle_aead`](https://crates.io/crates/tc_sparkle_aead) — SCHWAEMM on
  the SPARKLE permutation

### [tc_macs](https://github.com/TomiCheng/tc_macs)

- [`tc_macs`](https://crates.io/crates/tc_macs) — MAC traits plus CBC-MAC,
  CFB-MAC, CMAC, GMAC and HMAC
- [`tc_poly1305`](https://crates.io/crates/tc_poly1305) — Poly1305 (RFC 8439)

### [tc_key_wrap](https://github.com/TomiCheng/tc_key_wrap)

- [`tc_key_wrap`](https://crates.io/crates/tc_key_wrap) — key-wrap traits and
  the RFC 3394, RFC 5649 and RFC 3211 wrappers
- [`tc_des_wrap`](https://crates.io/crates/tc_des_wrap) and
  [`tc_rc2_wrap`](https://crates.io/crates/tc_rc2_wrap) — CMS Triple-DES and
  RC2 key wrapping (RFC 3217)
- [`tc_dstu7624_wrap`](https://crates.io/crates/tc_dstu7624_wrap) — DSTU 7624
  (Kalyna) key wrapping

### [tc_crypto](https://github.com/TomiCheng/tc_crypto)

- [`tc_buffered_cipher`](https://crates.io/crates/tc_buffered_cipher) — one
  buffered interface over block modes, stream ciphers, AEADs and asymmetric
  block ciphers, after Bouncy Castle's `IBufferedCipher`

### [tc_asym_cipher](https://github.com/TomiCheng/tc_asym_cipher)

- [`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher) — asymmetric
  block-cipher and key-pair-generator contracts
- [`tc_rsa`](https://crates.io/crates/tc_rsa) — RSA key generation, blinding
  and the RSA operation over fixed-width, padded and RustCrypto engines
- [`tc_asym_encoding`](https://crates.io/crates/tc_asym_encoding) — PKCS#1 v1.5
  and OAEP
- [`tc_asym_iso9796`](https://crates.io/crates/tc_asym_iso9796) — ISO/IEC
  9796-1 signatures with message recovery

## Incubating in this workspace

- [`crypto/tc_security`](crypto/tc_security) — name- and OID-based factories
  after Bouncy Castle's `Org.BouncyCastle.Security`: digests, ciphers, MACs,
  key wrap, key and parameter generation, key agreement and signers, wired to
  the published crates above
- [`crypto/tc_cfrg_curves`](crypto/tc_cfrg_curves) — X25519, X448, Ed25519 and
  Ed448 in one crate
- [`crypto/tc_ec_key`](crypto/tc_ec_key),
  [`crypto/agreement`](crypto/agreement) and [`signer`](signer) — EC keys,
  key agreement (ECDH) and signers (RSA, DSA, ECDSA)
- [`crypto/tc_drbg`](crypto/tc_drbg) — deterministic random bit generators
- [`asn1`](asn1) — PKCS, X.509, X9 and CMS structures over the published
  `tc_asn1`; [`x509`](x509) has started on certificates over them
- [`kdf`](kdf) — key derivation (KDF1/2, the concatenation KDF, HKDF and
  SP 800-108), the DH and ECDH key-encryption-key derivations of CMS,
  password-based generators (PKCS#5, PKCS#12 and OpenSSL) and password
  hashing (bcrypt, scrypt and Argon2)
- [`ies`](ies) — the Integrated Encryption Scheme over a key agreement, a
  KDF and a MAC
- [`block_cipher`](block_cipher) — rewrites of Blowfish, CAST5/CAST6,
  IDEA, Noekeon, Rijndael, SEED, Serpent, Skipjack,
  TEA/XTEA and Twofish on the `tc_block_cipher` traits, waiting to
  graduate
- [`crypto/macs`](crypto/macs) — MAC families not yet graduated, such as
  SipHash and KMAC

## Implemented algorithms

The lists below cover this workspace and the graduated repositories together.

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
- GOST 34.11-94 and Skein 1.3, on the published GOST 28147 and Threefish
  engines
- ISAP Hash, Photon-Beetle Hash, Xoodyak Hash, and Haraka-256/512
- TupleHash, ParallelHash, `ShortenedDigest`, `Prehash`, and `NullDigest`

See the [tc_digest repository](https://github.com/TomiCheng/tc_digest) for
variant-level details and usage examples.

### Key derivation and password hashing

- KDF1, KDF2 and the concatenation KDF (NIST SP 800-56A) over any digest
- HKDF (RFC 5869)
- SP 800-108 counter, feedback and double-pipeline KDFs over any MAC
- The DH KEK of RFC 2631 and the ECDH KEK of RFC 5753
- PKCS#5 PBKDF1 and PBKDF2, PKCS#12 key derivation, and OpenSSL
  `EVP_BytesToKey`
- bcrypt with OpenBSD hash strings, scrypt (RFC 7914), and Argon2d, Argon2i
  and Argon2id (RFC 9106)

### Mathematics

- Signed arbitrary-precision `BigInt`
- Arithmetic, bitwise operations, shifts, conversions, and arbitrary-radix text
- GCD, modular inverse, modular exponentiation, and probable-prime operations
- The SEC named curves and SM2P256V1, each as a constant-time and a
  variable-time set, with wNAF, GLV, the τ-adic NAF and the fixed-base comb
- X25519/X448

## Feature model

The workspace uses three runtime levels:

| Level | Meaning |
| --- | --- |
| Core-only `no_std` | No allocator and no standard library. Used by the trait crates, stream ciphers, and the core-only block-cipher subset. |
| `no_std + alloc` | No standard library, but owned buffers and dynamically sized state are available. Required by digests, modes, wrappers, math, and some block ciphers. |
| `std` | The default where offered. It preserves the same algorithms and adds conveniences such as lazy caches or runtime CPU-feature detection. |

Notable `std` acceleration currently includes AES-NI for AES and Haraka.
The published `tc_blake` detects AVX2 for BLAKE2b and SSE2 for BLAKE2s
without `std`.
Portable implementations remain available when `std` is disabled.

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
# Representative block-cipher crate (all family crates are no_std)
cargo build -p tc_blowfish_v2 --locked

# Portable digest backend without std
cargo build -p tc_misc_digest --features haraka --locked
```

`cargo test` always uses Rust's standard-library test harness. Use `cargo build`
with the feature combinations above to verify the library's actual `no_std`
configuration.

Benchmarks are available in the algorithm crates:

```bash
cargo bench -p tc_cfrg_curves --bench agreement
```

## Reference and license

Algorithm behavior and test vectors are compared with the
[Bouncy Castle C# source](https://github.com/bcgit/bc-csharp). This attribution
does not imply compatibility certification or endorsement.

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option (SPDX: `MIT OR Apache-2.0`).
