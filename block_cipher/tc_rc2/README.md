# tc_rc2_v2

RC2 single-block encryption with 1- to 128-byte keys, an 8-byte block and
an independently selected effective key size from 1 to 1024 bits.

**Variable time:** secret bytes index the PI table during key setup, and mash
rounds index subkeys with block data. Use only where cache-timing leakage is
outside the threat model; there is no constant-time alternative. Stored
schedules are wiped on drop, but caller buffers and all temporary copies are not.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_rc2_v2::{Params, Rc2Engine};

let mut engine = Rc2Engine::new();
let key = [0x42; 16];
engine.init(CipherDirection::Encrypt, &Params::with_effective_key_bits(&key, 63))?;
let mut output = [0; 8];
engine.process_block(&[0x11; 8], &mut output)?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

No mode, padding or authentication is provided.
