# tc_aria

ARIA-128, ARIA-192 and ARIA-256 single-block encryption, using the
`tc_block_cipher` interfaces. The crate is `no_std` and requires no allocator.

## Engines

| Type | Availability | Implementation |
| --- | --- | --- |
| `AriaEngine` | Always | RustCrypto with `rustcrypto`, otherwise Table |
| `AriaTableEngine` | Always | Portable S-box implementation |
| `AriaRustCryptoEngine` | `rustcrypto` feature | RustCrypto `aria` 0.2 |

Enable `rustcrypto` to select the RustCrypto backend through `AriaEngine`.
Its key-schedule wiping support is enabled with the feature.

**Neither backend is constant time.** Both key expansion and block processing
use secret-dependent table lookups. RustCrypto's ARIA implementation does not
have the same constant-time guarantee as its AES implementation.

## Usage

Import `BlockCipherInit` and `BlockCipher` from `tc_block_cipher`, create an
engine, and initialize it with a `CipherDirection` and `KeyRef`. Keys must
contain 16, 24 or 32 bytes. Every call to `process_block` transforms the first
16 bytes and leaves any output tail untouched.

Processing before initialization returns `NotInitialised`; short buffers return
`BufferTooShort`. These errors leave output unchanged. A rejected key length
preserves the prior key and direction. Call `init` again to change either.
All engines implement `Display` as `ARIA`, without exposing key material.

Stored schedules are wiped on drop, but caller buffers and other copies are
the caller's responsibility. This crate provides no mode, padding, nonce
management or authentication; use an appropriate authenticated-encryption
construction for messages.

## Checks

Run tests with both backend selections:

```text
cargo test -p tc_aria
cargo test -p tc_aria --all-features
```

Tests cover RFC 5794 known-answer vectors, key and buffer errors, reinitialization,
display, and differential checks between the two backends.

## Benchmarks

Compare Table and RustCrypto across all three key sizes:

```text
cargo bench -p tc_aria --bench aria --all-features
```

The suite measures encryption/decryption key setup and single-block
encryption/decryption directly on each backend, without the dispatcher.
Setup reinitialises an existing engine, including replacement of its previous
schedule; construction and final drop are excluded. Block timings exclude key
setup and report throughput for 16-byte blocks, not multi-block parallelism.

Each case warms up for 3 seconds and measures for 15 seconds. All 24 cases
take roughly 7–8 minutes, plus compilation and analysis. Without
`--all-features`, only the 12 Table cases run. Both backends are variable time;
these benchmarks do not verify constant-time behaviour.

Run only the block-processing comparison:

```text
cargo bench -p tc_aria --bench aria --all-features -- '^aria/(encrypt|decrypt)/'
```

Smoke-test all cases without collecting timing estimates:

```text
cargo bench -p tc_aria --bench aria --all-features -- --test
```

### Recorded results

Measured on 2026-09-24 with rustc 1.98.0, targeting
`x86_64-pc-windows-msvc`, using the optimized bench profile and all features.
All 24 cases completed, with 100 samples per case after the warm-up described
above. These are estimates from one local run, not portable performance guarantees.

Single-block throughput in MiB/s (higher is better):

| Key size | Table encrypt | RustCrypto encrypt | Table decrypt | RustCrypto decrypt |
| --- | ---: | ---: | ---: | ---: |
| 128-bit | 54.36 | 70.09 | 66.71 | 94.86 |
| 192-bit | 44.64 | 58.04 | 55.18 | 78.10 |
| 256-bit | 37.18 | 63.44 | 50.73 | 68.05 |

Key setup in ns per initialization (lower is better):

| Key size | Table encrypt | RustCrypto encrypt | Table decrypt | RustCrypto decrypt |
| --- | ---: | ---: | ---: | ---: |
| 128-bit | 231.65 | 397.29 | 377.75 | 311.64 |
| 192-bit | 271.57 | 372.24 | 414.23 | 346.89 |
| 256-bit | 284.18 | 395.39 | 436.45 | 404.37 |

RustCrypto had higher block throughput at every key size in this run. Table
had faster encryption key setup, while RustCrypto had faster decryption key
setup. Several cases showed noticeable variation and outliers; for example,
RustCrypto's 256-bit encryption measured faster than its 192-bit encryption.
Repeat measurements under controlled conditions before drawing conclusions
about small differences or scaling across key sizes.
