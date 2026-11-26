# KeyOwned

`KeyOwned` is always available (no feature is required). Import it and the `KeyParams` trait
from `tc_algo::params::key`. It holds raw secret key bytes for ciphers, MACs, and key wraps.

| Method | Setting | Valid range |
|---|---|---|
| `new(key)` | Takes ownership of the key bytes without copying | Depends on the target algorithm |

Construction validates nothing: each algorithm checks the key length when it is initialized
and returns `InvalidParams` if the length is not supported.

| Accessor | Returns |
|---|---|
| `KeyParams::key()` | The key bytes |

The key is wiped when the value is dropped.

## Use it with an algorithm

| Target | Params |
|---|---|
| ECB block ciphers, IV-less stream ciphers (such as `RC4`), MACs, key wraps | `KeyOwned` |
| Block or stream ciphers that take an IV | `KeyWithIvOwned` (build from `key.key().to_vec()`) |
| AEAD ciphers | `AeadParamsOwned` (build from `key.key().to_vec()`) |

The following example uses `AES/ECB/PKCS7PADDING` (requires the `aes` feature):

```rust
use tc_algo::params::key::KeyOwned;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 32-byte key for AES-256
    let key = KeyOwned::new(vec![0x42; 32]);
    let name = "AES/ECB/PKCS7PADDING";
    let _ciphertext = algo.cipher().encrypt_by_name(name, &key, b"attack at dawn")?;
    Ok(())
}
```

Most symmetric key generators return a `KeyOwned`. [Key generation](../KeyGeneration.md) ·
[Block cipher](../BlockCipher.md) · [MAC](../Mac.md)
