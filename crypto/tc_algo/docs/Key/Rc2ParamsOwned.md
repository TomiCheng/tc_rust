# Rc2ParamsOwned

Enable the `rc-cipher` feature to use `Rc2ParamsOwned`. Import it and the `Rc2Params` trait
from `tc_algo::params::key`. It holds an RC2 key and its effective key size, the number of
bits the RC2 key schedule reduces the key to.

| Method | Setting | Valid range |
|---|---|---|
| `new(key)` | Uses the whole key length as the effective key size | Key of 1–128 bytes |
| `with_effective_key_bits(key, bits)` | Sets the effective key size explicitly | Key of 1–128 bytes, 1–1024 bits |

With `new(key)`, a 16-byte key has 128 effective bits, the same as a `KeyOwned`. Construction
validates nothing: the cipher checks the key length and the effective key size when it is
initialized and returns `InvalidParams` for values outside these ranges.

| Accessor | Returns |
|---|---|
| `KeyParams::key()` | The key bytes |
| `Rc2Params::effective_key_bits()` | The effective key size in bits |

The key is wiped when the value is dropped, and `Debug` prints the key length, never the key.

## Use it with a cipher

| Rows | Params |
|---|---|
| ECB | `Rc2ParamsOwned` |
| CBC, CFB, OFB, CTR, GOFB, OPENPGPCFB | `ParamsWithIvOwned<Rc2ParamsOwned>` |
| EAX | `ParamsWithAeadOwned<Rc2ParamsOwned>` |

```rust
use tc_algo::params::cipher::ParamsWithIvOwned;
use tc_algo::params::key::Rc2ParamsOwned;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 16-byte key with 40 effective bits, and an 8-byte IV
    let rc2 = Rc2ParamsOwned::with_effective_key_bits(vec![0x42; 16], 40);
    let params = ParamsWithIvOwned::new(rc2, vec![0; 8]);
    let name = "RC2/CBC/PKCS7PADDING";
    let _ciphertext = algo.cipher().encrypt_by_name(name, &params, b"attack at dawn")?;
    Ok(())
}
```

The `RC2` key generator returns an `Rc2ParamsOwned`; see
[`Rc2KeyGenParams`](../KeyGeneration/Rc2KeyGenParams.md). [Key generation](../KeyGeneration.md) ·
[RC2](../Rc2.md)
