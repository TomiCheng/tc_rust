# tc_ccm

`tc_ccm` provides Counter with CBC-MAC (CCM) authenticated encryption over a
caller-selected 16-byte block cipher. The crate is `no_std`; the
`CcmBlockCipher<C>` engine uses `alloc` and is enabled by the default `alloc`
feature.

CCM is a packet mode. Calls to `process_aad_bytes()` and `process_bytes()`
buffer their input, while `do_final()` processes the complete packet. This
also means decryption does not expose plaintext until its authentication tag
has been verified successfully.

## Parameters

CCM accepts:

- a block cipher with a 16-byte block size;
- a nonce from 7 through 13 bytes;
- an even authentication-tag size from 4 through 16 bytes;
- optional initial associated data.

`tc_params::AeadBlockParams<'a>` borrows all byte slices. Applications may
instead supply their own type implementing `KeyParams`, `IvParams`,
`InitialAadParams`, and `MacSizeParams` from `tc_params`.

The MAC size passed to `AeadBlockParams::new()` is measured in bytes:

```rust
use tc_params::AeadBlockParams;

let key = [0x11_u8; 16];
let nonce = [0x22_u8; 12];
let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
```

## Encryption and decryption

```rust
use tc_aes::AesEngine;
use tc_ccm::CcmBlockCipher;
use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
use tc_params::AeadBlockParams;

let key = [0x11_u8; 16];
let nonce = [0x22_u8; 12];
let params = AeadBlockParams::new(&key, &nonce, 16, b"header");

let mut encryptor = CcmBlockCipher::new(AesEngine::new());
encryptor
    .init(CipherDirection::Encrypt, &params)
    .unwrap();
assert_eq!(encryptor.process_bytes(b"message", &mut []).unwrap(), 0);

let mut ciphertext = [0_u8; 7 + 16];
let written = encryptor.do_final(&mut ciphertext).unwrap();
assert_eq!(written, ciphertext.len());

let mut decryptor = CcmBlockCipher::new(AesEngine::new());
decryptor
    .init(CipherDirection::Decrypt, &params)
    .unwrap();
assert_eq!(decryptor.process_bytes(&ciphertext, &mut []).unwrap(), 0);

let mut recovered = [0_u8; 7];
let recovered_len = decryptor.do_final(&mut recovered).unwrap();
assert_eq!(recovered_len, recovered.len());
assert_eq!(&recovered, b"message");
```

Use `get_output_size()` to allocate the buffer passed to `do_final()` when the
packet length is not known at compile time. `get_update_output_size()` always
returns zero because CCM emits no partial packet output.

## Security and allocation behavior

- A key and nonce pair must never be reused for encryption. Reinitializing the
  same engine for encryption with the same pair is rejected.
- Additional authenticated data must be supplied before message data.
- On decryption, an invalid tag returns an authentication error without
  copying unauthenticated plaintext into the caller's output buffer.
- The engine clears its buffered AAD, message, and temporary plaintext after
  finalization.
- Building with `--no-default-features` omits `CcmBlockCipher`; the parameter
  type and size constants remain available without allocation.

## Verification

The tests include Bouncy Castle CCM vectors, a 64 KiB AAD vector, a long-data
vector, nonce/message-length boundaries, nonce reuse, and tamper detection:

```bash
cargo test -p tc_ccm --locked
cargo test -p tc_ccm --release --locked
cargo test -p tc_ccm --no-default-features --locked
cargo clippy -p tc_ccm --all-targets --no-deps --locked -- -D warnings
cargo doc -p tc_ccm --no-deps --locked
```
