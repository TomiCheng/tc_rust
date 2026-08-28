# tc_stream_cipher

## 1. Overview

`tc_stream_cipher` provides pure-Rust stream cipher implementations ported
from the Bouncy Castle C# engine package. All engines implement the
[`StreamCipher`](../tc_crypto_core) trait from `tc_crypto_core`.

A stream cipher generates a keystream and XORs it with the input. Encryption
and decryption are therefore normally the same operation, but the
`for_encryption` argument is retained for parity with Bouncy Castle's
`IStreamCipher` interface.

The crate supports `no_std` without requiring `alloc`. Parameter types own
their key and nonce material in fixed-size storage, and their `Debug`
implementations must not expose secret bytes.

> This crate is a learning port and has not received an independent security
> audit. Do not use it as a replacement for an audited cryptographic library.
> RC4, VMPC, and several other algorithms listed below are legacy designs and
> should not be selected for new protocols.

## 2. Usage

Add both the implementation crate and the trait crate to the application:

```toml
[dependencies]
tc_crypto_core = { path = "../tc_crypto_core" }
tc_stream_cipher = { path = "../tc_stream_cipher" }
```

Import `StreamCipher` to call `init`, `process_bytes`, `return_byte`, and
`reset`:

```rust
use tc_crypto_core::StreamCipher;
use tc_stream_cipher::{Rc4Engine, Rc4Error, Rc4Params};

fn main() -> Result<(), Rc4Error> {
    let params = Rc4Params::new(b"Key")?;
    let plaintext = b"Plaintext";

    let mut cipher = Rc4Engine::new();
    cipher.init(true, &params)?;

    let mut ciphertext = [0u8; 9];
    let written = cipher.process_bytes(plaintext, &mut ciphertext)?;
    assert_eq!(written, plaintext.len());

    cipher.init(false, &params)?;

    let mut recovered = [0u8; 9];
    cipher.process_bytes(&ciphertext, &mut recovered)?;
    assert_eq!(&recovered, plaintext);

    Ok(())
}
```

`process_bytes` writes exactly one output byte for each input byte. The output
slice must therefore be at least as long as the input slice. `reset` restarts
the keystream using the parameters supplied by the most recent `init` call.

Never reuse the same key and nonce/IV pair for algorithms that take a nonce.
Doing so reuses the keystream and can reveal relationships between plaintexts.

## 3. Bouncy Castle stream cipher inventory

The Bouncy Castle C# `engines` directory contains 11 public stream-cipher
engine types in six families. The table below is the implementation roadmap
for this crate.

| Family | Bouncy Castle engine | Key size | Nonce / IV size | Status |
|--------|----------------------|----------|-----------------|--------|
| RC4 | `RC4Engine` | 1-256 bytes in this crate | None | Implemented as `Rc4Engine` |
| HC | `HC128Engine` | 16 bytes | 16 bytes | Implemented as `Hc128Engine` |
| HC | `HC256Engine` | 16 or 32 bytes | At least 16 bytes | Implemented as `Hc256Engine` |
| ISAAC | `IsaacEngine` | 0-1024 bytes | None | Implemented as `IsaacEngine` |
| Salsa | `Salsa20Engine` | 16 or 32 bytes | 8 bytes | Implemented as `Salsa20Engine` |
| Salsa | `XSalsa20Engine` | 32 bytes | 24 bytes | Implemented as `Xsalsa20Engine` |
| ChaCha | `ChaChaEngine` | 16 or 32 bytes | 8 bytes | Implemented as `ChaChaEngine` |
| ChaCha | `ChaCha7539Engine` | 32 bytes | 12 bytes | Implemented as `ChaCha7539Engine` |
| ChaCha | `XChaCha20Engine` | 32 bytes | 24 bytes | Implemented as `XChaCha20Engine` |
| VMPC | `VmpcEngine` | 16-64 bytes | 16-64 bytes | Not implemented |
| VMPC | `VmpcKsa3Engine` | 16-64 bytes | 16-64 bytes | Not implemented |

Notes about the upstream behavior:

- `Salsa20Engine` and `ChaChaEngine` use 20 rounds by default and also accept
  a positive, even round count. `XSalsa20Engine` and `XChaCha20Engine` are the
  extended-nonce variants.
- `ChaCha7539Engine` is the IETF ChaCha construction with a 96-bit nonce and a
  32-bit block counter. `XChaCha20Engine` derives a subkey with HChaCha20 and
  then uses that construction.
- Bouncy Castle currently accepts 16- or 32-byte HC-256 keys and IVs of at
  least 16 bytes. Its source contains a note that a future API should strictly
  require 32 bytes for both.
- ISAAC accepts keys from zero through 1,024 bytes. BC does not validate this
  explicitly and would fail while loading a longer key; the Rust parameter
  constructor reports an `InvalidKeyLength` error instead.
- Salsa20-derived engines enforce a per-IV output limit. Matching counter and
  output-limit behavior is part of each future port, not an optional API
  detail.

The inventory deliberately excludes:

- `KCtrBlockCipher`, because it is a block-cipher counter mode and belongs with
  modes rather than native stream-cipher engines;
- `StreamBlockCipher`, because it is an adapter/base type rather than a cipher
  algorithm;
- authenticated ciphers such as ChaCha20-Poly1305 and XChaCha20-Poly1305,
  because AEAD engines require a separate authenticated-cipher API.

## 4. Implemented algorithms

### Original ChaCha

`ChaChaEngine` implements BC's original ChaCha construction with a 64-bit
counter, an 8-byte nonce, and a 16- or 32-byte key. It uses 20 rounds by
default; `ChaChaEngine::with_rounds` also exposes BC's positive, even custom
round counts, including ChaCha12 and ChaCha8. This API is distinct from the
IETF `ChaCha7539Engine`, which uses a 12-byte nonce and a 32-bit counter.

Tests cover BC vectors for ChaCha20, ChaCha12, and ChaCha8; both key sizes;
counter behavior through byte 65,600; reset; chunking; byte-at-a-time
processing; encryption/decryption symmetry; parameter validation; and runtime
errors.

### ChaCha7539 and XChaCha20

`ChaCha7539Engine` implements the IETF ChaCha20 construction with a 32-byte
key, 12-byte nonce, and 32-bit block counter. `XChaCha20Engine` extends the
nonce to 24 bytes: HChaCha20 derives a subkey from the first 16 nonce bytes,
then the remaining 8 bytes are used with ChaCha7539. Both engines use fixed
buffers and remain available without `std` or `alloc`.

Tests cover the RFC 8439 ChaCha7539 encryption vector, the BC XChaCha20 draft
vector, the HChaCha20 derivation vector, reset, chunking, byte-at-a-time
processing, encryption/decryption symmetry, parameter validation, runtime
errors, and 32-bit counter exhaustion.

### Salsa20 and XSalsa20

`Salsa20Engine` accepts 16- or 32-byte keys and an 8-byte nonce. It uses 20
rounds by default, while `Salsa20Engine::with_rounds` exposes BC's positive,
even custom-round configuration, including Salsa20/12 and Salsa20/8.
`Xsalsa20Engine` implements the 32-byte-key, 24-byte-nonce extended construction
using HSalsa20 subkey derivation. Both enforce BC's per-nonce output limit.

Tests cover BC vectors for Salsa20/20, Salsa20/12, and Salsa20/8; both Salsa20
key sizes; counter behavior through byte 65,600; NaCl/BC XSalsa20 vectors;
reset; chunking; byte-at-a-time processing; encryption/decryption symmetry;
parameter validation; and runtime errors.

### ISAAC

`IsaacEngine` implements Bob Jenkins' Indirection, Shift, Accumulate, Add, and
Count generator using BC's byte ordering and stream-cipher behavior. It accepts
keys from zero through the full 1,024-byte state capacity for compatibility
with BC. Tests cover BC known-answer vectors for 4-byte and 1,024-byte keys,
reset, processing across a keystream-block boundary, chunking, byte-at-a-time
processing, encryption/decryption symmetry, parameter validation, and runtime
errors.

### HC-128 and HC-256

`Hc128Engine` implements HC-128 with its required 16-byte key and 16-byte IV.
`Hc256Engine` preserves the current Bouncy Castle compatibility rules: it
accepts 16- or 32-byte keys and IVs of at least 16 bytes, then normalizes them
to the canonical 32-byte HC-256 state input. Tests cover official and ECRYPT
known-answer vectors for all four 128/256-bit key and IV size combinations,
plus reset, chunking, byte-at-a-time processing, parameter validation, and
runtime errors.

### RC4

`Rc4Engine` implements the Bouncy Castle `RC4Engine` behavior and accepts keys
from 1 through 256 bytes. Tests cover published known-answer vectors,
encryption/decryption symmetry, reset behavior, byte-at-a-time processing,
chunked processing, key validation, initialization state, and output buffer
validation.

RC4 has serious statistical biases and is prohibited by modern protocols such
as TLS. It is included only for compatibility, study, and migration of legacy
data.

## 5. Building and testing

The default build enables `std`:

```bash
cargo build -p tc_stream_cipher --locked
cargo test -p tc_stream_cipher --locked
```

Disable default features to build the library as `no_std` without `alloc`.
Tests still link the Rust standard test harness, but exercise the
no-default-features library configuration:

```bash
cargo build -p tc_stream_cipher --no-default-features --locked
cargo test -p tc_stream_cipher --no-default-features --locked
```

Additional validation:

```bash
cargo clippy -p tc_stream_cipher --all-targets --locked -- -D warnings
cargo clippy -p tc_stream_cipher --all-targets --no-default-features --locked -- -D warnings
cargo rustdoc -p tc_stream_cipher --locked -- -D warnings
```
