# tc_grain128_aead

`tc_grain128_aead` implements the Grain-128AEAD authenticated-encryption
algorithm. Grain-128AEAD uses a 16-byte key, a 12-byte nonce, and an 8-byte
authentication tag.

The crate is `no_std`. Its default `alloc` feature provides a growable engine;
an allocation-free fixed-capacity engine is always available.

## Implementations

| Type | AAD storage | Availability |
|------|-------------|--------------|
| `Engine` | Growable `Vec<u8>` | Default `alloc` feature |
| `FixedEngine<const MAX_AAD_LEN: usize>` | `[u8; MAX_AAD_LEN]` | Always available |

Both engines use the same Grain-128AEAD implementation. They differ only in
how associated data is buffered before message processing begins.

Internally, a private generic engine owns the key, nonce, shift registers,
authentication state, tag buffer, and AEAD state machine. A small internal AAD
buffer interface is implemented by both `Vec<u8>` and the fixed array. The two
public engine types delegate to this shared implementation, so the cipher and
authentication calculations are not duplicated.

Grain-128AEAD authenticates an encoding of the total AAD length before it
authenticates the AAD bytes themselves. Consequently, `process_aad_bytes()`
buffers its input. The first call to `process_bytes()` or `do_final()` obtains
the actual buffered length and then processes:

```text
Encode(AAD length) || AAD || message
```

Callers therefore do not declare the exact AAD length as an initialization
parameter.

### Growable engine

`Engine` accepts any AAD length supported by the allocator:

```rust
use tc_grain128_aead::Engine;

let engine = Engine::new();
```

The default features enable this type. To use the crate without an allocator,
disable default features.

### Fixed-capacity engine

`FixedEngine` stores AAD directly in the engine. Its const parameter is a
capacity, not the exact AAD length:

```rust
use tc_grain128_aead::FixedEngine;

let engine = FixedEngine::<1024>::new();
assert_eq!(engine.max_aad_len(), 1024);
```

The example above accepts any AAD length from 0 through 1024 bytes. Additional
AAD returns `AeadError::AadTooLong`. Initial AAD larger than the capacity makes
initialization return `InitError::InitialAadTooLong`.

## Parameters

The convenience `Params<'a>` type borrows its key, nonce, and initial AAD
without copying them:

```rust
use tc_grain128_aead::Params;

let key = [0_u8; 16];
let nonce = [0_u8; 12];
let params = Params::new(&key, &nonce, b"header");
```

Applications do not have to use this concrete type. Both engines accept any
caller-owned parameter type implementing:

```rust
tc_params::KeyParams
    + tc_params::IvParams
    + tc_params::InitialAadParams
```

The engines validate key and nonce lengths during initialization.

## Processing

Associated data must be supplied before the first plaintext or ciphertext
byte. It may be split across multiple calls:

```rust
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
use tc_grain128_aead::{Engine, Params, TAG_BYTES};

let key = [0_u8; 16];
let nonce = [0_u8; 12];
let params = Params::new(&key, &nonce, &[]);
let mut cipher = Engine::new();

cipher.init(CipherDirection::Encrypt, &params)?;
cipher.process_aad_bytes(b"head")?;
cipher.process_aad_bytes(b"er")?;

let plaintext = b"message";
let mut ciphertext_and_tag = [0_u8; 7 + TAG_BYTES];
let mut written = cipher.process_bytes(plaintext, &mut ciphertext_and_tag)?;
written += cipher.do_final(&mut ciphertext_and_tag[written..])?;
assert_eq!(written, ciphertext_and_tag.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

During decryption, `process_bytes()` may return plaintext before the
authentication tag has been checked. Do not release or act on that plaintext
until `do_final()` succeeds.

## Features and verification

Build and test the default growable implementation:

```bash
cargo test -p tc_grain128_aead --locked
```

Build and test the fixed implementation without an allocator:

```bash
cargo test -p tc_grain128_aead --no-default-features --test fixed_engine --locked
```
