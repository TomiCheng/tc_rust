# Gost28147KeyGenParams

Enable the `gost28147` feature to use the `GOST28147` key generator. Import
`Gost28147KeyGenParams` from `tc_algo::params::generate`.

| Method | Setting | Valid length |
|---|---|---|
| `new()` | Selects the default S-box | |
| `with_s_box(s_box)` | Supplies an S-box | 128 bytes |

The generated key is always 32 bytes. `generate_by_name("GOST28147")` uses the default S-box.
When you supply an S-box, `init` checks its length and returns `InvalidParams` for any
length other than 128 bytes.

## Generate a key

```rust
use tc_algo::params::{generate::Gost28147KeyGenParams, key::gost28147_s_box};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = Gost28147KeyGenParams::new().with_s_box(gost28147_s_box::E_A.to_vec());
    let _key = algo.key_generator().generate_by_name_with("GOST28147", &params)?;
    Ok(())
}
```

The generator returns a `Gost28147ParamsOwned` inside `Box<dyn Params>` with the generated key
and the selected S-box. [Key generation](../KeyGeneration.md) · [GOST 28147](../BlockCipher/GOST28147.md)
