# RsaKeyGenParams

Enable the `rsa` feature to use the `RSA` key pair generator. Import `RsaKeyGenParams` from
`tc_algo::params::generate`.

| Method | Setting | Default | Valid range |
|---|---|---|---|
| `new(strength)` | Modulus size in bits | none | At least 16 bits (use at least 2048 for security) |
| `with_public_exponent(e)` | Public exponent | `65537` | Odd integer, at least 3 |
| `with_certainty(certainty)` | Prime test certainty | `100` | At least 1 |

`RSA` has no default key size, so `generate_by_name("RSA")` returns `NotInitialized`. With
`RsaKeyGenParams`, the generator validates all settings during `init` and returns
`InvalidParams` for values outside these ranges. `tc_rsa` accepts sizes far too small to be
safe, so choosing a safe key size is up to the caller.

| Accessor | Returns |
|---|---|
| `strength()` | Modulus size in bits (`u32`) |
| `public_exponent()` | Public exponent (`u32`) |
| `certainty()` | Prime test certainty (`u32`) |

## Generate a key pair

```rust
use tc_algo::params::generate::RsaKeyGenParams;
use tc_algo::params::key::{RsaKey, RsaKeyParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = RsaKeyGenParams::new(2048);
    let pair = algo.key_pair_generator().generate_by_name_with("RSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");
    let private = pair.private().as_any().downcast_ref::<RsaKey>().expect("an RsaKey");
    assert_eq!(public.modulus(), private.modulus());
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` and `private()` keys are both `RsaKey`
inside `Box<dyn Params>`. [Key pair generation](../KeyPairGeneration.md) · [RSA](../Rsa.md)
