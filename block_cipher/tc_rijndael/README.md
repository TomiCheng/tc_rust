# tc_rijndael_v2

Generalized Rijndael with 128-, 160-, 192-, 224- and 256-bit blocks
and keys in any combination. This allocator-free `no_std` crate
implements the `tc_block_cipher` interfaces.

**Variable time:** key setup and block processing use secret-dependent S-box
lookups; block processing also branches on secret data in field multiplication.
Use only where cache-timing leakage is outside the threat model;
this crate provides no constant-time alternative. Stored working keys are
wiped on drop; this does not wipe caller buffers or guarantee erasure of
every register or stack copy.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_rijndael_v2::Rijndael128Engine;

let mut engine = Rijndael128Engine::new();
let key = [0u8; 16];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 16];
engine.process_block(&[0u8; 16], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
