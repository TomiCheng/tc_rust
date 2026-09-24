# tc_sm4_v2

SM4 with a 16-byte key and 16-byte blocks. This allocator-free `no_std` crate
implements the `tc_block_cipher` interfaces.

**Variable time:** key setup and block processing use secret-dependent S-box
lookups. Use only where cache-timing leakage is outside the threat model;
this crate provides no constant-time alternative. Stored working keys are
wiped on drop; this does not wipe caller buffers or guarantee erasure of
every register or stack copy.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_sm4_v2::Sm4Engine;

let mut engine = Sm4Engine::new();
let key = [0u8; 16];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 16];
engine.process_block(&[0u8; 16], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
