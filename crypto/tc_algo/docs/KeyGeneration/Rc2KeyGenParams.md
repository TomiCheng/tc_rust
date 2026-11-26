# Rc2KeyGenParams

Enable the `rc-cipher` feature to use the `RC2` key generator. Import
`Rc2KeyGenParams` from `tc_algo::params::generate`.

| Method | Setting | Valid range |
|---|---|---|
| `new(key_bytes)` | Length of the generated key in bytes | 1–128 bytes |
| `with_effective_key_bits(bits)` | Effective key size used by the RC2 key schedule | 1–1024 bits |

The effective key size defaults to the generated key length in bits.
`generate_by_name("RC2")` uses the generator defaults of 16 bytes and 128 effective bits.
With explicit parameters, the generator validates both lengths during `init` and returns
`InvalidParams` for values outside these ranges.

## Generate a key

```rust
use tc_algo::params::generate::Rc2KeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = Rc2KeyGenParams::new(16).with_effective_key_bits(40);
    let _key = algo.key_generator().generate_by_name_with("RC2", &params)?;
    Ok(())
}
```

The generator returns an `Rc2ParamsOwned` inside `Box<dyn Params>`, carrying both the
generated key and its effective key size. [Key generation](../KeyGeneration.md) · [RC2](../Rc2.md)
