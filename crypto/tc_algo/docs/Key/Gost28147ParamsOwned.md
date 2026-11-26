# Gost28147ParamsOwned

Enable the `gost28147` feature to use `Gost28147ParamsOwned`. Import it, the
`Gost28147Params` trait, and named S-boxes (`gost28147_s_box`) from `tc_algo::params::key`.
It holds a GOST 28147-89 key and its S-box.

| Method | Setting | Valid length |
|---|---|---|
| `new(key)` | Pairs the key with the default S-box | Key of 32 bytes |
| `with_s_box(key, s_box)` | Pairs the key with an explicit S-box | Key of 32 bytes, S-box of 128 bytes |

With `new(key)`, the cipher uses the default S-box, the same as a `KeyOwned`. Construction
validates nothing: the cipher checks both lengths when it is initialized and returns
`InvalidParams` for any other length.

| Accessor | Returns |
|---|---|
| `KeyParams::key()` | The key bytes |
| `Gost28147Params::s_box()` | The S-box bytes |

Both the key and the S-box are wiped when the value is dropped, and `Debug` prints their
lengths, never their bytes.

## Use it with a cipher

| Rows | Params |
|---|---|
| ECB | `Gost28147ParamsOwned` |
| CBC, CFB, OFB, CTR, GOFB, OPENPGPCFB | `ParamsWithIvOwned<Gost28147ParamsOwned>` |
| EAX | `ParamsWithAeadOwned<Gost28147ParamsOwned>` |

```rust
use tc_algo::params::cipher::ParamsWithIvOwned;
use tc_algo::params::key::{Gost28147ParamsOwned, gost28147_s_box};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 32-byte key with CryptoPro's E_A S-box, and an 8-byte IV
    let gost = Gost28147ParamsOwned::with_s_box(vec![0x42; 32], gost28147_s_box::E_A.to_vec());
    let params = ParamsWithIvOwned::new(gost, vec![0; 8]);
    let name = "GOST28147/CBC/PKCS7PADDING";
    let _ciphertext = algo.cipher().encrypt_by_name(name, &params, b"attack at dawn")?;
    Ok(())
}
```

The `GOST28147` key generator returns a `Gost28147ParamsOwned`; see
[`Gost28147KeyGenParams`](../KeyGeneration/Gost28147KeyGenParams.md).
[Key generation](../KeyGeneration.md) · [GOST 28147](../Gost28147.md)
