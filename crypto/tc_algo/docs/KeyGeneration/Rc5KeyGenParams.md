# Rc5KeyGenParams

Enable the `rc-cipher` feature to use the `RC5` and `RC5-64` key generators. Import
`Rc5KeyGenParams` from `tc_algo::params::generate`.

| Method | Setting | Valid range |
|---|---|---|
| `new(key_bytes)` | Length of the generated key in bytes | 1–255 bytes |
| `with_rounds(rounds)` | Number of RC5 rounds | 0–255 |

The round count defaults to 12. Without explicit parameters, `RC5` (alias `RC5-32`)
generates a 16-byte key, and `RC5-64` generates a 32-byte key. The generator validates
the settings during `init` and returns `InvalidParams` for values outside these ranges.

## Generate a key

```rust
use tc_algo::params::generate::Rc5KeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = Rc5KeyGenParams::new(32).with_rounds(16);
    let _key = algo.key_generator().generate_by_name_with("RC5-64", &params)?;
    Ok(())
}
```

The generator returns an `Rc5ParamsOwned` inside `Box<dyn Params>`, carrying both the
generated key and its round count. [Key generation](../KeyGeneration.md) · [RC5](../BlockCipher/RC5.md)
