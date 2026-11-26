# ThreefishKeyGenParams

Enable the `threefish` feature to use the Threefish key generators. Import
`ThreefishKeyGenParams` from `tc_algo::params::generate`.

| Method | Setting | Valid length |
|---|---|---|
| `new()` | Selects the default all-zero tweak | |
| `with_tweak(tweak)` | Supplies a tweak | 16 bytes |

The algorithm name determines the generated key length. `THREEFISH-256`, `THREEFISH-512`,
and `THREEFISH-1024` generate 32, 64, and 128 bytes respectively. Calling `generate_by_name`
uses the default tweak. When you supply a tweak, `init` checks its length and returns
`InvalidParams` for any length other than 16 bytes.

## Generate a key

```rust
use tc_algo::params::generate::ThreefishKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = ThreefishKeyGenParams::new().with_tweak(vec![1; 16]);
    let _key = algo.key_generator().generate_by_name_with("THREEFISH-512", &params)?;
    Ok(())
}
```

The generator returns a `ThreefishParamsOwned` inside `Box<dyn Params>` with the generated key
and the selected tweak. [Key generation](../KeyGeneration.md) · [Threefish](../Threefish.md)
