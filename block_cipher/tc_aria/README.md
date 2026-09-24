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
