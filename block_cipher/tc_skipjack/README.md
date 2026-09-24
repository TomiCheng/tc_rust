# tc_skipjack_v2

SKIPJACK with a 10-byte key and 8-byte blocks. This allocator-free `no_std` crate
implements the `tc_block_cipher` interfaces.

**Variable time:** block processing uses secret-dependent F-table
lookups. Use only where cache-timing leakage is outside the threat model;
this crate provides no constant-time alternative. Stored working keys are
wiped on drop; this does not wipe caller buffers or guarantee erasure of
every register or stack copy.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_skipjack_v2::SkipjackEngine;

let mut engine = SkipjackEngine::new();
let key = [0u8; 10];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 8];
engine.process_block(&[0u8; 8], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
