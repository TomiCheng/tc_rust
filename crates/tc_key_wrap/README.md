# tc_key_wrap

## 1. Overview

`tc_key_wrap` provides pure-Rust *key-wrapping* algorithms ported from the
Bouncy Castle C# engine package. A key wrapper encrypts key material under a
key-encryption key (KEK), producing a slightly longer blob that carries its own
integrity check, so a tampered blob or the wrong KEK is rejected on unwrap.

All wrappers implement the [`Wrapper`](../tc_crypto_core/src/wrapper.rs) trait
from `tc_crypto_core` and build on a block cipher from
[`tc_block_cipher`](../tc_block_cipher). Because a wrapped blob has an
input-dependent length, `wrap` and `unwrap` return an owned `Vec<u8>`; the crate
is therefore `no_std + alloc`.

> This crate is a learning port and has not received an independent security
> audit. Do not use it as a replacement for an audited cryptographic library.

**Status: in progress.** The `Wrapper` trait exists in `tc_crypto_core`; the
RFC 3394 and RFC 5649 AES Key Wrap families and the DSTU 7624 wrap are complete
and KAT-verified. Only the CBC-based wrappers remain — see the checklist in §4.
This document is the porting inventory and roadmap.

## 2. Design

Bouncy Castle expresses most wrappers as a thin subclass that fixes the
underlying cipher of a generic RFC engine — e.g. `AesWrapEngine : Rfc3394WrapEngine`.
The Rust port mirrors this with generics plus type aliases:

```rust
pub struct Rfc3394WrapEngine<E: BlockCipher> { /* engine, key, iv, direction */ }
pub type AesWrapEngine      = Rfc3394WrapEngine<AesEngine>;
pub type CamelliaWrapEngine = Rfc3394WrapEngine<CamelliaEngine>;
```

The wrappers fall into three mechanism families:

- **AES Key Wrap (RFC 3394 / 5649).** Operate directly on the block cipher's ECB
  primitive; no cipher mode needed. RFC 3394 wraps a key that is a multiple of 8
  bytes; RFC 5649 adds padding so any length is accepted.
- **CMS / RFC 3217 & RFC 3211.** Older schemes that run the cipher in **CBC**
  mode with an IV, and (for RFC 3217) append a **SHA-1** checksum.
- **DSTU 7624 (Kalyna).** A national-standard wrap with its own checksum.

## 3. Engines to port

Twelve Bouncy Castle wrap classes, grouped by mechanism. "Prereqs" lists what
must exist in this workspace before the engine can be ported.

### 3.1 AES Key Wrap family — done

| bc class | Rust target | Underlying cipher | Mechanism | Prereqs |
|----------|-------------|-------------------|-----------|---------|
| `Rfc3394WrapEngine` ✅ | `Rfc3394WrapEngine<E>` | any 128-bit-block cipher | RFC 3394, unpadded | — (base engine) |
| `Rfc5649WrapEngine` ✅ | `Rfc5649WrapEngine<E>` | any 128-bit-block cipher | RFC 5649, padded (wraps RFC 3394) | RFC 3394 engine |
| `AesWrapEngine` ✅ | `AesWrapEngine` alias | `AesEngine` | RFC 3394 | RFC 3394 engine |
| `AesWrapPadEngine` ✅ | `AesWrapPadEngine` alias | `AesEngine` | RFC 5649 | RFC 5649 engine |
| `AriaWrapEngine` ✅ | `AriaWrapEngine` alias | `AriaEngine` | RFC 3394 | RFC 3394 engine |
| `AriaWrapPadEngine` ✅ | `AriaWrapPadEngine` alias | `AriaEngine` | RFC 5649 | RFC 5649 engine |
| `CamelliaWrapEngine` ✅ | `CamelliaWrapEngine` alias | `CamelliaEngine` | RFC 3394 | RFC 3394 engine |
| `SeedWrapEngine` ✅ | `SeedWrapEngine` alias | `SeedEngine` | RFC 3394 | RFC 3394 engine |

All underlying ciphers (AES, ARIA, Camellia, SEED) already exist in
`tc_block_cipher`, so this whole family unblocks as soon as the two base engines
(`Rfc3394WrapEngine`, then `Rfc5649WrapEngine`) are written.

### 3.2 CMS / RFC 3217 & RFC 3211 — blocked on CBC mode

| bc class | Rust target | Underlying cipher | Mechanism | Prereqs |
|----------|-------------|-------------------|-----------|---------|
| `Rfc3211WrapEngine` | `Rfc3211WrapEngine<E>` | any block cipher | RFC 3211, CBC + IV, constant-time compare | **CBC mode** |
| `DesEdeWrapEngine` | `DesEdeWrapEngine` | `DesEdeEngine` | RFC 3217, CBC + fixed IV + SHA-1 checksum | **CBC mode**, SHA-1 |
| `Rc2WrapEngine` | `Rc2WrapEngine` | `Rc2Engine` | RFC 3217, CBC + IV + SHA-1 checksum | **CBC mode**, SHA-1 |

These need a **CBC block-cipher mode**, which does not exist in the workspace yet
(`tc_block_cipher` ships only the raw ECB engines). SHA-1 is available in
`tc_digest` (`sha1.rs`). Porting these should wait until a modes crate exists.

### 3.3 DSTU 7624 (Kalyna) — done

| bc class | Rust target | Underlying cipher | Mechanism | Prereqs |
|----------|-------------|-------------------|-----------|---------|
| `Dstu7624WrapEngine` ✅ | `Dstu7624WrapEngine` | `Dstu7624Engine` | DSTU 7624 wrap, own checksum | selects block size |

`Dstu7624Engine` already exists in `tc_block_cipher`; this wrapper carries its
own logic and does not depend on a cipher mode.

## 4. TODO (porting order)

- [x] **`Rfc3394WrapEngine<E>`** — the foundation; verified against the NIST AES
  Key Wrap known-answer vectors (`tests/rfc3394_kat.rs`).
- [x] **AES/ARIA/Camellia/SEED `WrapEngine` aliases** — type aliases plus a
  `Default` impl for arg-less construction. AES is covered by the RFC 3394 NIST
  vectors; ARIA/Camellia/SEED are cross-checked against an independent
  OpenSSL-based RFC 3394 implementation (`tests/wrap_alias_kat.rs`).
- [x] **`Rfc5649WrapEngine<E>`** + `AesWrapPadEngine` / `AriaWrapPadEngine` — AES
  verified against the RFC 5649 §6 official vectors, ARIA cross-checked against
  the independent OpenSSL implementation (`tests/rfc5649_kat.rs`). Shares the
  RFC 3394 register core.
- [x] **`Dstu7624WrapEngine`** — its own swap-network scheme over the DSTU 7624
  cipher (128/256/512-bit blocks), verified against the Bouncy Castle key-wrap
  vectors (`tests/dstu7624_kat.rs`).
- [ ] **CBC-based wrappers** (`Rfc3211WrapEngine`, `DesEdeWrapEngine`,
  `Rc2WrapEngine`) — only after a CBC mode exists in the workspace.
