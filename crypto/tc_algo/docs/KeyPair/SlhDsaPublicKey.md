# SlhDsaPublicKey and SlhDsaPrivateKey

Enable the `slh-dsa` feature and import `SlhDsaPublicKey` and `SlhDsaPrivateKey` from
`tc_algo::params::key`. The `SLH-DSA` key pair generator returns an `SlhDsaPublicKey` and an
`SlhDsaPrivateKey`, the keys of FIPS 205.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `params` | The parameter set, an [`SlhDsaParameters`](../KeyPairGeneration/SlhDsaParameters.md) | yes | yes | `params()` |
| `encoding` | The bytes of the key: `PK.seed ‖ PK.root` for a public key, `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` for a private one | yes | yes | `encoding()` |

`params` is an `SlhDsaParameters` by value and `encoding` a `Vec<u8>`. Each part is `n` bytes,
16, 24 or 32 as the set has it, so a public key is `2n` bytes and a private key `4n`. The parts
have no accessors of their own. The private key also gives its public key with `public_key()`. A
key is built from the same fields:

| Build | Gives |
|---|---|
| `SlhDsaPublicKey::from_encoding(params, &bytes)` | The public key, or `InvalidKeyLength` |
| `SlhDsaPrivateKey::from_encoding(params, &bytes)` | The private key, with `PK.root` as given; or `InvalidKeyLength` |
| `SlhDsaPrivateKey::from_seeds(params, &sk_seed, &sk_prf, &pk_seed)` | The private key, with `PK.root` computed from the seeds; or `InvalidKeyLength` |

The constructors check the lengths, and nothing else: `from_encoding` takes `PK.root` as it is,
while `from_seeds` computes it, as key generation does, which takes a while for the `S` sets. Both
keys are `Clone`. The public key is `Debug` and `PartialEq`; the private key is neither, and it
wipes `SK.seed` and `SK.prf` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::SlhDsaParameters;
use tc_algo::params::key::{SlhDsaPrivateKey, SlhDsaPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = SlhDsaParameters::SHA2_128F;
    let pair = algo.key_pair_generator().generate_by_name_with("SLH-DSA", &params)?;

    // The keys of the pair
    let public = pair.public().as_any().downcast_ref::<SlhDsaPublicKey>().expect("an SlhDsaPublicKey");
    let private = pair.private().as_any().downcast_ref::<SlhDsaPrivateKey>().expect("an SlhDsaPrivateKey");

    // Build the same keys again from their fields
    let _public1 = SlhDsaPublicKey::from_encoding(public.params(), &public.encoding())?;
    let _private1 = SlhDsaPrivateKey::from_encoding(private.params(), &private.encoding())?;
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| SLH-DSA rows, such as `SLH-DSA-SHA2-128F` | Verifies | Signs |
| HashSLH-DSA rows, such as `SLH-DSA-SHA2-128F-WITH-SHA256` | Verifies | Signs |

A key goes only to the rows of its own parameter set.

## Keys that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A key of another parameter set than the row | `init` | `InvalidParams` |
| An encoding of the wrong length for its `params` | `from_encoding` | `InvalidKeyLength` |
| A private key whose `PK.root` is not the one of its seeds | Only in use | Its signatures do not verify |
| A public key that is not the one of the private key | Only in use | `verify` gives `false` |

To check that two keys belong together, compare `public_key()` of the private key with the public
key: the public keys are `PartialEq`. To check `PK.root` of a private key, build it again with
`from_seeds` and compare the public keys.

[Key pair generation](../KeyPairGeneration.md) · [SLH-DSA](../SlhDsa.md) ·
[SlhDsaParameters](../KeyPairGeneration/SlhDsaParameters.md)
