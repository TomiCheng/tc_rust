# Rc5ParamsOwned

Enable the `rc-cipher` feature to use `Rc5ParamsOwned`. Import it and the `Rc5Params` trait
from `tc_algo::params::key`. It holds an RC5 key and its round count for both `RC5` (alias
`RC5-32`, 8-byte block) and `RC5-64` (16-byte block).

| Method | Setting | Valid range |
|---|---|---|
| `new(key, rounds)` | Sets an explicit round count | Key of 1–255 bytes, 0–255 rounds |
| `with_default_rounds(key)` | Uses the default 12 rounds | Key of 1–255 bytes |

With `with_default_rounds(key)`, the cipher uses 12 rounds, the same as a `KeyOwned`.
Construction validates nothing: the cipher checks the key length and the round count when it
is initialized and returns `InvalidParams` for values outside these ranges.

| Accessor | Returns |
|---|---|
| `KeyParams::key()` | The key bytes |
| `Rc5Params::rounds()` | The round count |

The key is wiped when the value is dropped, and `Debug` prints the key length and round
count, never the key.

## Use it with a cipher

| Rows | Params |
|---|---|
| ECB | `Rc5ParamsOwned` |
| CBC, CFB, OFB, CTR, GOFB (`RC5`), OPENPGPCFB | `ParamsWithIvOwned<Rc5ParamsOwned>` |
| EAX; for `RC5-64` also GCM, CCM, OCB, KCCM | `ParamsWithAeadOwned<Rc5ParamsOwned>` |
| GCM-SIV of `RC5-64` | not taken: `AeadParamsOwned` with a bare key only |

In the modes with an IV the params go with the IV, as Bouncy Castle's
`ParametersWithIV(RC5Parameters, iv)`. In the AEAD modes they go with the nonce, the tag size and
the initial AAD in a `ParamsWithAeadOwned`, which Bouncy Castle has no counterpart of: its
`AeadParameters` takes a `KeyParameter` alone.

```rust
use tc_algo::params::cipher::ParamsWithIvOwned;
use tc_algo::params::key::Rc5ParamsOwned;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 16-byte key with 16 rounds, and an 8-byte IV for RC5 (RC5-32)
    let rc5 = Rc5ParamsOwned::new(vec![0x42; 16], 16);
    let params = ParamsWithIvOwned::new(rc5, vec![0; 8]);
    let name = "RC5/CBC/PKCS7PADDING";
    let _ciphertext = algo.cipher().encrypt_by_name(name, &params, b"attack at dawn")?;
    Ok(())
}
```

The `RC5` and `RC5-64` key generators return an `Rc5ParamsOwned`; see
[`Rc5KeyGenParams`](../KeyGeneration/Rc5KeyGenParams.md). [Key generation](../KeyGeneration.md) ·
[RC5](../BlockCipher/RC5.md)
