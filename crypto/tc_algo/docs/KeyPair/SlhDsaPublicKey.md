# SlhDsaPublicKey and SlhDsaPrivateKey

Enable `slh-dsa` and import `SlhDsaPublicKey`, `SlhDsaPrivateKey`, and `SlhDsaParameters` from
`tc_algo::params::key`. The `SLH-DSA` generator returns these key types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `params` | Parameter set | yes | yes | `params()` |
| `seed` | Public seed | yes | via `public` | `encoding()` |
| `root` | Public tree root | yes | via `public` | `encoding()` |
| `sk_seed` | Secret seed | | yes | `encoding()` |
| `sk_prf` | Secret PRF key | | yes | `encoding()` |
| Public key | Corresponding public components |  | yes | `public_key()` |

| Build | Gives |
|---|---|
| `SlhDsaPublicKey::from_encoding(params, bytes)` | Public key or `InvalidKeyLength` |
| `SlhDsaPrivateKey::from_encoding(params, bytes)` | Private key or `InvalidKeyLength` |
| `SlhDsaPrivateKey::from_seeds(params, sk_seed, sk_prf, pk_seed)` | Key or `InvalidKeyLength` |

The byte constructors check lengths. The private constructor accepts the supplied public root.
The seed constructor checks each seed's length and computes this root. Dropping the private key
wipes its secret seed and secret PRF key.
The public key implements `Debug` and `PartialEq`. The private key omits those traits.

## Read and build a key pair

```rust
use tc_algo::params::key::{SlhDsaParameters, SlhDsaPrivateKey, SlhDsaPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = SlhDsaParameters::SHA2_128F;
    let pair = algo.key_pair_generator().generate_by_name_with("SLH-DSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<SlhDsaPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<SlhDsaPrivateKey>().unwrap();

    let _public1 = SlhDsaPublicKey::from_encoding(public.params(), &public.encoding())?;
    let _private1 = SlhDsaPrivateKey::from_encoding(private.params(), &private.encoding())?;
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| SLH-DSA rows such as `SLH-DSA-SHA2-128F` | Verifies | Signs |
| HashSLH-DSA rows such as `SLH-DSA-SHA2-128F-WITH-SHA256` | Verifies | Signs |

[Key pair generation](../KeyPairGeneration.md) ·
[SlhDsa](../SlhDsa.md) ·
[SlhDsaParameters](../KeyPairGeneration/SlhDsaParameters.md)
