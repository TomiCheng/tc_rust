# tc_ascon_aead

`tc_ascon_aead` provides the finalized NIST Ascon-AEAD128 algorithm and three
incompatible legacy Ascon v1.2 AEAD variants. The crate is `no_std`, does not
allocate, and supports incremental AAD and message processing.

## Algorithms

| Module | Algorithm | Key | Nonce | Tag | Rate |
|--------|-----------|----:|------:|----:|-----:|
| `aead128` | NIST SP 800-232 Ascon-AEAD128 | 16 bytes | 16 bytes | 16 bytes | 16 bytes |
| `legacy` | Ascon-128 v1.2 | 16 bytes | 16 bytes | 16 bytes | 8 bytes |
| `legacy` | Ascon-128a v1.2 | 16 bytes | 16 bytes | 16 bytes | 16 bytes |
| `legacy` | Ascon-80pq v1.2 | 20 bytes | 16 bytes | 16 bytes | 8 bytes |

New protocols should use `aead128::Engine`. The legacy variants exist only for
compatibility with data or protocols that explicitly require Ascon v1.2.
Finalized Ascon-AEAD128 changed details including its byte ordering, IV, and
padding, so it cannot decrypt ciphertext produced by any legacy variant.

All four algorithms use a fixed 16-byte authentication tag. Consequently,
initialization does not accept a configurable `mac_size` parameter.

## Parameters

`Params<'a>` borrows its key, nonce, and initial AAD without copying them. The
same type is available through all of these paths:

```rust
tc_ascon_aead::Params
tc_ascon_aead::aead128::Params
tc_ascon_aead::legacy::Params
```

The selected engine validates key and nonce lengths during initialization.
Applications may use `Params<'a>` for convenience or provide their own type
implementing `KeyParams`, `IvParams`, and `InitialAadParams` from `tc_params`.

## Finalized Ascon-AEAD128

```rust
use tc_ascon_aead::aead128::{Engine, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};

let key = [0_u8; KEY_BYTES];
let nonce = [1_u8; NONCE_BYTES];
let params = Params::new(&key, &nonce, b"header");
let mut cipher = Engine::new();

cipher.init(CipherDirection::Encrypt, &params)?;
let plaintext = b"message";
let mut output = [0_u8; 7 + TAG_BYTES];
let mut written = cipher.process_bytes(plaintext, &mut output)?;
written += cipher.do_final(&mut output[written..])?;
assert_eq!(written, output.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Legacy Ascon v1.2

Select the exact legacy construction with `legacy::Variant`:

```rust
use tc_ascon_aead::legacy::{Engine, KEY_BYTES_80PQ, NONCE_BYTES, Params, TAG_BYTES, Variant};
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};

let key = [0_u8; KEY_BYTES_80PQ];
let nonce = [1_u8; NONCE_BYTES];
let params = Params::new(&key, &nonce, &[]);
let mut cipher = Engine::new(Variant::Ascon80pq);

cipher.init(CipherDirection::Encrypt, &params)?;
cipher.process_aad_bytes(b"header")?;
let plaintext = b"message";
let mut output = [0_u8; 7 + TAG_BYTES];
let mut written = cipher.process_bytes(plaintext, &mut output)?;
written += cipher.do_final(&mut output[written..])?;
assert_eq!(written, output.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Associated data must be supplied before plaintext or ciphertext. During
decryption, `process_bytes()` may produce unauthenticated plaintext; callers
must not release or act on it until `do_final()` successfully verifies the
tag.

## Verification

Run the finalized NIST vectors, legacy v1.2 vectors, doctests, and API tests:

```bash
cargo test -p tc_ascon_aead --locked
```

The state transitions must also be checked in optimized builds:

```bash
cargo test -p tc_ascon_aead --release --locked
```

Run lint and documentation checks:

```bash
cargo clippy -p tc_ascon_aead --all-targets --locked -- -D warnings
cargo doc -p tc_ascon_aead --no-deps --locked
```
