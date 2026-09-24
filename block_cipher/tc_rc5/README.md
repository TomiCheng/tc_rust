# tc_rc5_v2

RC5-32 and RC5-64 single-block engines with 1- to 255-byte keys and 0 to
255 rounds. Their blocks are 8 and 16 bytes respectively.

**Constant time** on mainstream x86, x86-64 and AArch64 processors with
operand-independent rotations; processors without a barrel shifter can leak.
Stored schedules are wiped on replacement and drop, but caller buffers and
all register or stack copies are not guaranteed to be erased.

## Usage

```rust
use tc_block_cipher::{BlockCipher, BlockCipherInit, CipherDirection};
use tc_rc5_v2::{Params, Rc532Engine};

let mut engine = Rc532Engine::new();
let key = [0x42; 16];
engine.init(CipherDirection::Encrypt, &Params::with_default_rounds(&key))?;
let mut output = [0; 8];
engine.process_block(&[0x11; 8], &mut output)?;
# Ok::<(), Box<dyn core::error::Error>>(())
```

No mode, padding or authentication is provided.
