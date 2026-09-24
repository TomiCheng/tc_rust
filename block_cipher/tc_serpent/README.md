# tc_serpent_v2

Serpent and Tnepres use a 16-byte block and 4- to 32-byte keys in four-byte
steps. This allocator-free `no_std` crate implements `tc_block_cipher`.
Tnepres uses a different byte representation and is not a Serpent alias.

**Constant time with respect to key and block contents:** both engines use
bitsliced S-boxes with Boolean operations and fixed rotations. Stored
schedules are wiped on drop; caller buffers and every register or stack
copy are not.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_serpent_v2::SerpentEngine;

let mut engine = SerpentEngine::new();
let key = [0u8; 16];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 16];
engine.process_block(&[0u8; 16], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
