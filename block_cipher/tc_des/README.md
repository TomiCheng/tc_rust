# tc_des_v2

DES and Triple DES with 8-byte blocks, for legacy interoperability only.
DES accepts an 8-byte encoded key; Triple DES accepts 16 or 24 bytes.
Parity bits are ignored and weak keys are accepted. Do not use in new designs. This allocator-free `no_std` crate
implements the `tc_block_cipher` interfaces.

**Variable time:** key setup and block processing use secret-dependent SP-box
lookups and key-bit branches. Use only where cache-timing leakage is outside the threat model;
this crate provides no constant-time alternative. Stored working keys are
wiped on drop; this does not wipe caller buffers or guarantee erasure of
every register or stack copy.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_des_v2::DesEdeEngine;

let mut engine = DesEdeEngine::new();
let key = [0u8; 24];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 8];
engine.process_block(&[0u8; 8], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
