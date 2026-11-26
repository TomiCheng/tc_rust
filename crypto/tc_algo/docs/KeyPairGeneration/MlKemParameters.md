# MlKemParameters

Enable the `ml-kem` feature to use the `ML-KEM` key pair generator. Import `MlKemParameters`
from `tc_algo::params::generate`, and the key types from `tc_algo::params::key`.

An `MlKemParameters` is both the input of the generator and part of each key, so
`tc_algo::params::key` exports it too. The two paths name the same type.

## Generate a key pair

```rust
use tc_algo::params::generate::MlKemParameters;
use tc_algo::params::key::{MlKemPrivateKey, MlKemPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The parameter set is the input of the generator
    let params: MlKemParameters = MlKemParameters::ML_KEM_768;
    let pair = algo.key_pair_generator().generate_by_name_with("ML-KEM", &params)?;

    let public = pair.public().as_any().downcast_ref::<MlKemPublicKey>().expect("an MlKemPublicKey");
    let private = pair.private().as_any().downcast_ref::<MlKemPrivateKey>().expect("an MlKemPrivateKey");

    // Each key carries its parameter set
    assert_eq!(public.params(), params);
    assert_eq!(private.params(), params);
    assert_eq!(public.encoding().len(), params.public_key_length());
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is an `MlKemPublicKey` and whose `private()`
is an `MlKemPrivateKey`, each inside `Box<dyn Params>`. The keys draw from the source of
`DefaultAlgoBuilder::set_rand`.

`ML-KEM` has no default parameter set, so `generate_by_name("ML-KEM")` returns `NotInitialized`.
Any params other than an `MlKemParameters` are `InvalidParams`.

## Parameter sets

The three sets of FIPS 203. Each is a constant; there is nothing to build or check. A key of one
set goes only to the KEM row of the same name.

| Constant | KEM row | Security category | Public key bytes | Private key bytes | Encapsulation bytes |
|---|---|---|---|---|---|
| `MlKemParameters::ML_KEM_512` | `ML-KEM-512` | 1 | 800 | 1632 | 768 |
| `MlKemParameters::ML_KEM_768` | `ML-KEM-768` | 3 | 1184 | 2400 | 1088 |
| `MlKemParameters::ML_KEM_1024` | `ML-KEM-1024` | 5 | 1568 | 3168 | 1568 |

The shared secret is 32 bytes for all three. NIST recommends `ML_KEM_768` as the default.

| Accessor | Returns |
|---|---|
| `name()` | The name, for instance `"ML-KEM-768"` (`&'static str`) |
| `public_key_length()` | Bytes of the public key (`usize`) |
| `private_key_length()` | Bytes of the private key (`usize`) |
| `encapsulation_length()` | Bytes of the encapsulation (`usize`) |
| `secret_length()` | Bytes of the shared secret, 32 (`usize`) |

`MlKemParameters` is `Copy`, so the keys' `params()` return it by value, and two sets are equal
when they are the same constant.

[Key pair generation](../KeyPairGeneration.md) · [KEM](../KEM.md)
