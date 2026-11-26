# MlKemPublicKey and MlKemPrivateKey

Enable the `ml-kem` feature and import `MlKemPublicKey` and `MlKemPrivateKey` from
`tc_algo::params::key`. The `ML-KEM` key pair generator returns an `MlKemPublicKey`, the
encapsulation key `ek` of FIPS 203, and an `MlKemPrivateKey`, the decapsulation key `dk`.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `params` | The parameter set, an [`MlKemParameters`](../KeyPairGeneration/MlKemParameters.md) | yes | yes | `params()` |
| `encoding` | The bytes of `ek` or of `dk` | yes | yes | `encoding()` |
| `seed` | The 64 bytes `d ‖ z` that `dk` was generated from, when known | | yes | `seed()` |

`params` is an `MlKemParameters` by value, `encoding` a `&[u8]` and `seed` an
`Option<&[u8; 64]>`. The private key also gives its public key, read out of `dk`, with
`public_key()`. A key is built from the same fields:

| Build | Gives |
|---|---|
| `MlKemPublicKey::from_encoding(params, ek)` | The public key |
| `MlKemPrivateKey::from_seed(params, seed)` | The private key, `dk` computed from the seed, which it keeps |
| `MlKemPrivateKey::from_encoding(params, dk)` | The private key, with no seed |

The seed is the short form of a private key, 64 bytes against the 1632 to 3168 of `dk`; a key
built from `dk` alone has no seed to give back.

Nothing is checked when a key is built. The KEM rows check a key at `init`: that its parameter
set is that of the row, and its `validate()`, which for a public key checks the length and that
every coefficient is below `q`, and for a private key the length and the hash of `ek` inside
`dk`. Both keys are `Clone`. The public key is `Debug` and `PartialEq`; the private key is
neither, and it wipes `dk` and the seed when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::MlKemParameters;
use tc_algo::params::key::{MlKemPrivateKey, MlKemPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = MlKemParameters::ML_KEM_768;
    let pair = algo.key_pair_generator().generate_by_name_with("ML-KEM", &params)?;

    // The keys of the pair
    let public = pair.public().as_any().downcast_ref::<MlKemPublicKey>().expect("an MlKemPublicKey");
    let private = pair.private().as_any().downcast_ref::<MlKemPrivateKey>().expect("an MlKemPrivateKey");

    // Build the same keys again from their fields
    let _public1 = MlKemPublicKey::from_encoding(public.params(), public.encoding().to_vec());

    // The private key from its seed when it has one, otherwise from dk
    let _private1 = match private.seed() {
        Some(seed) => MlKemPrivateKey::from_seed(private.params(), *seed),
        None => MlKemPrivateKey::from_encoding(private.params(), private.encoding().to_vec()),
    };
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024` | Encapsulates | Decapsulates |

A key goes only to the row of its own parameter set.

## Keys that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A key of another parameter set than the row | `init` | `InvalidParams` |
| An encoding of the wrong length for its `params` | `init` | `InvalidParams` |
| A `dk` whose hash of `ek` does not match | `init` of the decapsulator | `InvalidParams` |
| An encapsulation made to another public key than the one of the private key | Only in use | `decapsulate` gives `Ok` with a different secret, as FIPS 203 requires; it shows when what follows, a MAC or an AEAD cipher, fails |

[Key pair generation](../KeyPairGeneration.md) · [KEM](../KEM.md) ·
[MlKemParameters](../KeyPairGeneration/MlKemParameters.md)
