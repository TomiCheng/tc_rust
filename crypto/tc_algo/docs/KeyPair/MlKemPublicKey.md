# MlKemPublicKey and MlKemPrivateKey

Enable `ml-kem` and import `MlKemPublicKey`, `MlKemPrivateKey`, and `MlKemParameters` from
`tc_algo::params::key`. The `ML-KEM` generator returns these key types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `params` | Parameter set | yes | yes | `params()` |
| `encoding` | Public or private key material | yes | yes | `encoding()` |
| Public components | The public key carried in the private key bytes | | yes | `public_key()` |
| `seed` | Optional 64-byte key generation seed |  | yes | `seed()` |

| Build | Gives |
|---|---|
| `MlKemPublicKey::from_encoding(params, bytes)` | Public key |
| `MlKemPrivateKey::from_encoding(params, bytes)` | Private key without seed |
| `MlKemPrivateKey::from_seed(params, seed)` | Private key with seed |

The byte constructors store the input as supplied. The KEM calls `validate()` at initialization.
It checks the public key length and coefficient bounds, or the private key length and
embedded public key hash. Dropping the private key wipes its bytes and retained seed.
The public key implements `Debug` and `PartialEq`. The private key omits those traits.

## Read and build a key pair

```rust
use tc_algo::params::key::{MlKemParameters, MlKemPrivateKey, MlKemPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = MlKemParameters::ML_KEM_768;
    let pair = algo.key_pair_generator().generate_by_name_with("ML-KEM", &params)?;

    let public = pair.public().as_any().downcast_ref::<MlKemPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<MlKemPrivateKey>().unwrap();

    let _public1 = MlKemPublicKey::from_encoding(public.params(), public.encoding().to_vec());
    let Some(seed) = private.seed() else {
        unreachable!("the generator retains the seed");
    };
    let _private1 = MlKemPrivateKey::from_seed(private.params(), *seed);
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Encapsulates | Decapsulates |

[Key pair generation](../KeyPairGeneration.md) ·
[KEM](../KEM.md) ·
[MlKemParameters](../KeyPairGeneration/MlKemParameters.md)
