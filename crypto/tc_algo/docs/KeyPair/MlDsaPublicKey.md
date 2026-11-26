# MlDsaPublicKey and MlDsaPrivateKey

Enable the `ml-dsa` feature and import `MlDsaPublicKey` and `MlDsaPrivateKey` from
`tc_algo::params::key`. The `ML-DSA` key pair generator returns an `MlDsaPublicKey` and an
`MlDsaPrivateKey`, the keys of FIPS 204.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `params` | The parameter set, an [`MlDsaParameters`](../KeyPairGeneration/MlDsaParameters.md) | yes | yes | `params()` |
| `encoding` | The bytes of the key: `ρ ‖ t1` for a public key, `ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0` for a private one | yes | yes | `encoding()` |
| `seed` | The 32 bytes `ξ` the key was generated from, when known | | yes | `seed()` |

`params` is an `MlDsaParameters` by value, `encoding` a `Vec<u8>` and `seed` an
`Option<&[u8; 32]>`. The parts of an encoding have no accessors of their own. The private key also
gives its public key with `public_key()`. A key is built from the same fields:

| Build | Gives |
|---|---|
| `MlDsaPublicKey::from_encoding(params, &bytes)` | The public key, or `InvalidKeyLength` |
| `MlDsaPrivateKey::from_seed(params, seed)` | The private key, computed from the seed, which it keeps |
| `MlDsaPrivateKey::from_encoding(params, &bytes)` | The private key with `t1` computed again, and no seed; or `InvalidKeyLength` |

The seed is the short form of a private key, 32 bytes against the 2560 to 4896 of the encoding; a
key built from its encoding has no seed to give back.

The constructors from an encoding check its length, and nothing else. Both keys are `Clone`. The
public key is `Debug` and `PartialEq`; the private key is neither, and it wipes the seed, `K`,
`s1`, `s2` and `t0` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::MlDsaParameters;
use tc_algo::params::key::{MlDsaPrivateKey, MlDsaPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = MlDsaParameters::ML_DSA_65;
    let pair = algo.key_pair_generator().generate_by_name_with("ML-DSA", &params)?;

    // The keys of the pair
    let public = pair.public().as_any().downcast_ref::<MlDsaPublicKey>().expect("an MlDsaPublicKey");
    let private = pair.private().as_any().downcast_ref::<MlDsaPrivateKey>().expect("an MlDsaPrivateKey");

    // Build the same keys again from their fields
    let _public1 = MlDsaPublicKey::from_encoding(public.params(), &public.encoding())?;

    // The private key from its seed when it has one, otherwise from its encoding
    let _private1 = match private.seed() {
        Some(seed) => MlDsaPrivateKey::from_seed(private.params(), *seed),
        None => MlDsaPrivateKey::from_encoding(private.params(), &private.encoding())?,
    };
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | Verifies | Signs |
| HashML-DSA rows, such as `ML-DSA-65-WITH-SHA512` | Verifies | Signs |

A key goes only to the rows of its own parameter set.

## Keys that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A key of another parameter set than the row | `init` | `InvalidParams` |
| An encoding of the wrong length for its `params` | `from_encoding` | `InvalidKeyLength` |
| A public key that is not the one of the private key | Only in use | `verify` gives `false` |

To check that two keys belong together, compare `public_key()` of the private key with the public
key: the public keys are `PartialEq`.

[Key pair generation](../KeyPairGeneration.md) · [ML-DSA](../MlDsa.md) ·
[MlDsaParameters](../KeyPairGeneration/MlDsaParameters.md)
