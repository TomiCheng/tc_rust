# tc_gost28147_v2

GOST 28147-89 single-block encryption with a 32-byte key, an 8-byte block and a
caller-selected S-box. `KeyWithSBox` uses the default table unless overridden.

**Variable time:** rounds use S-box lookups indexed by secret nibbles. Use only
where cache-timing leakage is outside the threat model; there is no constant-time
alternative. Stored subkeys and S-boxes are wiped on drop, but caller buffers
and all register or stack copies are not guaranteed to be erased.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_gost28147_v2::{Gost28147Engine, KeyWithSBox};

let mut engine = Gost28147Engine::new();
let key = [0x42; 32];
engine.init(CipherDirection::Encrypt, &KeyWithSBox::new(&key))?;
let mut output = [0; 8];
engine.process_block(&[0x11; 8], &mut output)?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

No mode, padding or authentication is provided.
