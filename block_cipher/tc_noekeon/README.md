# tc_noekeon_v2

Noekeon in direct-key mode, with a 16-byte key and 16-byte blocks. This
allocator-free `no_std` crate implements the `tc_block_cipher` interfaces.

**Constant time with respect to key and block contents.** The engine uses
bitwise operations and fixed rotations, with no secret-dependent branches or
table lookups. The stored working key is wiped on drop; caller buffers and
every register or stack copy are not.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_noekeon_v2::NoekeonEngine;

let mut engine = NoekeonEngine::new();
let key = [0u8; 16];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 16];
engine.process_block(&[0u8; 16], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
