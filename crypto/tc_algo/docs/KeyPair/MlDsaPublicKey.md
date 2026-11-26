# MlDsaPublicKey and MlDsaPrivateKey

Enable `ml-dsa` and import `MlDsaPublicKey`, `MlDsaPrivateKey`, and `MlDsaParameters` from
`tc_algo::params::key`. The `ML-DSA` generator returns these key types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `params` | Parameter set | yes | yes | `params()` |
| `rho` | Public matrix seed | yes | yes | `encoding()` |
| `t1` | High part of the public vector | yes | yes | `encoding()` on the public key |
| `k` | Secret signing seed | | yes | `encoding()` |
| `tr` | Public key hash | | yes | `encoding()` |
| `s1` | First secret vector | | yes | `encoding()` |
| `s2` | Second secret vector | | yes | `encoding()` |
| `t0` | Low part of the public vector | | yes | `encoding()` |
| Public key | Corresponding public components |  | yes | `public_key()` |
| `seed` | Optional 32-byte key generation seed |  | yes | `seed()` |

| Build | Gives |
|---|---|
| `MlDsaPublicKey::from_encoding(params, bytes)` | Public key or `InvalidKeyLength` |
| `MlDsaPrivateKey::from_encoding(params, bytes)` | Private key or `InvalidKeyLength` |
| `MlDsaPrivateKey::from_seed(params, seed)` | Private key with seed |

The byte constructors check lengths. The private constructor derives the public components.
Dropping the private key wipes its retained seed and secret material.
The public key implements `Debug` and `PartialEq`. The private key omits those traits.

## Read and build a key pair

```rust
use tc_algo::params::key::{MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = MlDsaParameters::ML_DSA_65;
    let pair = algo.key_pair_generator().generate_by_name_with("ML-DSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<MlDsaPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<MlDsaPrivateKey>().unwrap();

    let _public1 = MlDsaPublicKey::from_encoding(public.params(), &public.encoding())?;
    let Some(seed) = private.seed() else {
        unreachable!("the generator retains the seed");
    };
    let _private1 = MlDsaPrivateKey::from_seed(private.params(), *seed);
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | Verifies | Signs |
| HashML-DSA rows such as `ML-DSA-65-WITH-SHA512` | Verifies | Signs |

[Key pair generation](../KeyPairGeneration.md) ·
[MlDsa](../MlDsa.md) ·
[MlDsaParameters](../KeyPairGeneration/MlDsaParameters.md)
