# tc_tea_v2

TEA and XTEA single-block engines using a 16-byte key and an 8-byte block.
Keys and blocks use big-endian words; the two algorithms are not interchangeable.

**Constant time** with respect to key and block contents, using addition, XOR and
fixed shifts. Stored schedules are wiped on replacement and drop, but caller
buffers and all register or stack copies are not guaranteed to be erased.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection, KeyRef};
use tc_tea_v2::XteaEngine;

let mut engine = XteaEngine::new();
engine.init(CipherDirection::Encrypt, &KeyRef::new(&[0x42; 16]))?;
let mut output = [0; 8];
engine.process_block(&[0x11; 8], &mut output)?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

No mode, padding or authentication is provided.
