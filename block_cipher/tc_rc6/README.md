# tc_rc6_v2

RC6-32/20 with 1- to 255-byte keys and 16-byte blocks, using the
`tc_block_cipher` interfaces in an allocator-free `no_std` crate.

**Constant time under hardware assumptions:** data-dependent rotations and
32-bit multiplications must have fixed latency, as on mainstream x86, x86-64
and AArch64. Processors without a barrel shifter or with early-terminating
multipliers can leak secrets. Stored schedules are wiped on drop; caller
buffers and every register or stack copy are not.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_rc6_v2::Rc6Engine;

let mut engine = Rc6Engine::new();
let key = [0u8; 16];
engine.init(CipherDirection::Encrypt, &KeyRef::new(&key)).unwrap();
let mut ciphertext = [0u8; 16];
engine.process_block(&[0u8; 16], &mut ciphertext).unwrap();
```

This crate provides no mode, padding or authentication.
