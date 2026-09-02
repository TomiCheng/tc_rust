# tc_chacha_aead

`tc_chacha_aead` provides incremental ChaCha authenticated encryption without
requiring `std` or allocation.

## Algorithms

| Type | Stream cipher | Key | Nonce | Tag |
|------|---------------|----:|------:|----:|
| `ChaCha20Poly1305` | IETF ChaCha20 (`ChaCha7539Engine`) | 32 bytes | 12 bytes | 16 bytes |
| `XChaCha20Poly1305` | XChaCha20 (`XChaCha20Engine`) | 32 bytes | 24 bytes | 16 bytes |

`ChaCha20Poly1305` implements RFC 8439. `XChaCha20Poly1305` uses HChaCha20 and
the extended 192-bit nonce construction described by the XChaCha draft. Both
types share the same internal AEAD processing core and use
`tc_poly1305::Engine` for authentication.

The authentication tag is always 16 bytes, so initialization does not accept
a configurable `mac_size` parameter.

## Parameters

`Params<'a>` borrows its key, nonce, and initial associated data without
copying them:

```rust
use tc_chacha_aead::Params;

let key = [0x11_u8; 32];
let nonce = [0x22_u8; 12];
let params = Params::new(&key, &nonce, b"header");
```

Applications may instead provide their own parameter type implementing
`KeyParams`, `IvParams`, and `InitialAadParams` from `tc_params`.

## ChaCha20-Poly1305

```rust
use tc_chacha_aead::{ChaCha20Poly1305, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};

let key = [0x11_u8; KEY_BYTES];
let nonce = [0x22_u8; NONCE_BYTES];
let params = Params::new(&key, &nonce, b"header");
let plaintext = b"message";

let mut cipher = ChaCha20Poly1305::new();
cipher.init(CipherDirection::Encrypt, &params).unwrap();

let mut ciphertext = [0_u8; 7 + TAG_BYTES];
let mut written = cipher.process_bytes(plaintext, &mut ciphertext).unwrap();
written += cipher.do_final(&mut ciphertext[written..]).unwrap();
assert_eq!(written, ciphertext.len());
```

## XChaCha20-Poly1305

The API is identical, but the nonce is 24 bytes:

```rust
use tc_chacha_aead::{Params, TAG_BYTES, XChaCha20Poly1305, XNONCE_BYTES};
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};

let key = [0x11_u8; 32];
let nonce = [0x22_u8; XNONCE_BYTES];
let params = Params::new(&key, &nonce, b"header");

let mut cipher = XChaCha20Poly1305::new();
cipher.init(CipherDirection::Encrypt, &params).unwrap();

let mut ciphertext = [0_u8; 7 + TAG_BYTES];
let mut written = cipher.process_bytes(b"message", &mut ciphertext).unwrap();
written += cipher.do_final(&mut ciphertext[written..]).unwrap();
assert_eq!(written, ciphertext.len());
```

## Security and streaming behavior

- A key and nonce pair must never be reused for encryption. Reinitializing the
  same engine for encryption with the same pair returns `InitError::NonceReuse`.
- Additional authenticated data must be supplied before message data. Initial
  AAD from `Params` is processed during initialization; more AAD may be added
  with `process_aad_bytes()` before the first `process_bytes()` call.
- During decryption, `process_bytes()` may emit unauthenticated plaintext. Do
  not release or act on it until `do_final()` successfully verifies the tag.
- The engine retains the trailing 16 ciphertext bytes as the tag and uses a
  fixed 80-byte internal buffer. No allocation is required.

## Verification

Run the RFC 8439 and XChaCha draft vectors, API tests, and doctests:

```bash
cargo test -p tc_chacha_aead --locked
cargo test -p tc_chacha_aead --release --locked
```

Run lint and documentation checks:

```bash
cargo clippy -p tc_chacha_aead --all-targets --locked -- -D warnings
cargo doc -p tc_chacha_aead --no-deps --locked
```
