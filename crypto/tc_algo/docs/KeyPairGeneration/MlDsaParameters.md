# MlDsaParameters

Enable the `ml-dsa` feature to use the `ML-DSA` key pair generator. Import `MlDsaParameters`
from `tc_algo::params::generate`, and the key types from `tc_algo::params::key`.

An `MlDsaParameters` is both the input of the generator and part of each key, so
`tc_algo::params::key` exports it too. The two paths name the same type.

## Generate a key pair

```rust
use tc_algo::params::generate::MlDsaParameters;
use tc_algo::params::key::{MlDsaPrivateKey, MlDsaPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The parameter set is the input of the generator
    let params: MlDsaParameters = MlDsaParameters::ML_DSA_65;
    let pair = algo.key_pair_generator().generate_by_name_with("ML-DSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<MlDsaPublicKey>().expect("an MlDsaPublicKey");
    let private = pair.private().as_any().downcast_ref::<MlDsaPrivateKey>().expect("an MlDsaPrivateKey");

    // Each key carries its parameter set
    assert_eq!(public.params(), params);
    assert_eq!(private.params(), params);
    assert_eq!(public.encoding().len(), params.public_key_length());
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is an `MlDsaPublicKey` and whose `private()`
is an `MlDsaPrivateKey`, each inside `Box<dyn Params>`. The keys draw from the source of
`DefaultAlgoBuilder::set_rand`.

`ML-DSA` has no default parameter set, so `generate_by_name("ML-DSA")` returns `NotInitialized`.
Any params other than an `MlDsaParameters` are `InvalidParams`.

## Parameter sets

The three sets of FIPS 204. Each is a constant; there is nothing to build or check. A key of one
set goes only to the signer rows of the same name: `ML-DSA-65` and its prehash row
`ML-DSA-65-WITH-SHA512` for `ML_DSA_65`.

| Constant | Signer row | Security category | Public key bytes | Private key bytes | Signature bytes |
|---|---|---|---|---|---|
| `MlDsaParameters::ML_DSA_44` | `ML-DSA-44` | 2 | 1312 | 2560 | 2420 |
| `MlDsaParameters::ML_DSA_65` | `ML-DSA-65` | 3 | 1952 | 4032 | 3309 |
| `MlDsaParameters::ML_DSA_87` | `ML-DSA-87` | 5 | 2592 | 4896 | 4627 |

| Accessor | Returns |
|---|---|
| `name()` | The name, for instance `"ML-DSA-65"` (`&'static str`) |
| `public_key_length()` | Bytes of the public key (`usize`) |
| `private_key_length()` | Bytes of the private key (`usize`) |
| `signature_length()` | Bytes of a signature (`usize`) |

`MlDsaParameters` is `Copy`, so the keys' `params()` return it by value, and two sets are equal
when they are the same constant.

[Key pair generation](../KeyPairGeneration.md) · [ML-DSA](../MlDsa.md)
