# tc_threefish_v2

Threefish-256, Threefish-512 and Threefish-1024 single-block engines. The key
is one block long; the optional tweak is 16 bytes, defaulting to all zero.

**Constant time** with respect to key, tweak and block contents. Stored keys,
parity and tweaks are wiped on replacement and drop; caller buffers and all
register or stack copies are not guaranteed to be erased.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_threefish_v2::{Params, Threefish256Engine};

let mut engine = Threefish256Engine::new();
let key = [0x42; 32];
engine.init(CipherDirection::Encrypt, &Params::new(&key))?;
let mut output = [0; 32];
engine.process_block(&[0x11; 32], &mut output)?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

No mode, padding or authentication is provided.
