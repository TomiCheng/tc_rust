# tc_cast_v2

CAST5 with 5- to 16-byte keys and 8-byte blocks, and CAST6 with
16-, 20-, 24-, 28- or 32-byte keys and 16-byte blocks. This allocator-free `no_std` crate
implements the `tc_block_cipher` interfaces.

**Variable time:** key setup and block processing use secret-dependent S-box
lookups. Use only where cache-timing leakage is outside the threat model;
this crate provides no constant-time alternative. Stored working keys are
wiped on drop; this does not wipe caller buffers or guarantee erasure of
every register or stack copy.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_cast_v2::Cast6Engine;

let mut engine = Cast6Engine::new();
let key = [0u8; 16];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 16];
engine.process_block(&[0u8; 16], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
