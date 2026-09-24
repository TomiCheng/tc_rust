# tc_chacha_v2

The ChaCha stream ciphers on the `tc_stream_cipher` interfaces. It covers
the original ChaCha, IETF ChaCha20 (RFC 8439) and XChaCha20, and needs
neither `std` nor an allocator.

`ChaChaEngine`, `ChaCha7539Engine` and `XChaCha20Engine` pick their backend.
With the `rustcrypto` feature they run on RustCrypto's `chacha20`, which
uses SIMD where the processor has it. Enabling the feature never changes
which keys, nonces or round counts are accepted: 16-byte keys and reduced
rounds, which RustCrypto lacks, stay on the portable engine. The portable
and RustCrypto engines can also be used directly. See
[BENCHES.md](BENCHES.md) for measured speeds.

**Constant time:** every engine uses only 32-bit additions, XORs and fixed
rotations. Keystream state is wiped on drop; caller buffers and register or
stack copies are not.

## Usage

```rust
use tc_chacha_v2::ChaCha7539Engine;
use tc_stream_cipher::{CipherDirection, KeyWithIvRef, StreamCipher, StreamCipherInit};

let (key, nonce) = ([0u8; 32], [0u8; 12]);
let mut engine = ChaCha7539Engine::new();
engine.init(CipherDirection::Encrypt, &KeyWithIvRef::new(&key, &nonce)).unwrap();
let mut ciphertext = [0u8; 5];
engine.process_bytes(b"hello", &mut ciphertext).unwrap();
```

This crate provides no authentication. Never reuse a key and nonce pair,
and use an AEAD such as ChaCha20-Poly1305 to protect messages.
