# X25519 and X448 keys

Enable the `cfrg-curves` feature and import `X25519PublicKey`, `X25519PrivateKey`,
`X448PublicKey` and `X448PrivateKey` from `tc_algo::params::key`. The `X25519` and `X448` key pair
generators return them. The keys are the byte strings of RFC 7748, so each holds one fixed array.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `u` | The u-coordinate of the public point | yes | | `u()` |
| `k` | The private scalar, as bytes; it is clamped when it is used | | yes | `k()` |

| Key | Bytes of `u` and `k` |
|---|---|
| X25519 | 32 (`&[u8; 32]`) |
| X448 | 56 (`&[u8; 56]`) |

The private key also gives its public key with `generate_public_key()`. A key is built from the
same fields:

| Build | Gives |
|---|---|
| `X25519PublicKey::new(u)`, `X448PublicKey::new(u)` | The public key |
| `X25519PrivateKey::new(k)`, `X448PrivateKey::new(k)` | The private key |

Nothing is checked when a key is built; the arrays fix the lengths, and any `u` or `k` is accepted,
as RFC 7748 has it. The agreement refuses a secret of all zeros, which a public key of small order
gives, as `InvalidParams`. All four keys are `Clone`. The public keys are `Debug` and
`PartialEq`; the private keys are neither, and they wipe `k` when they are dropped.

## Read and build a key pair

```rust
use tc_algo::params::key::{X25519PrivateKey, X25519PublicKey, X448PrivateKey, X448PublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The curve is fixed, so X25519 and X448 take no params
    let pair = algo.key_pair_generator().generate_by_name("X25519")?;
    let public = pair.public().as_any().downcast_ref::<X25519PublicKey>().expect("an X25519PublicKey");
    let private = pair.private().as_any().downcast_ref::<X25519PrivateKey>().expect("an X25519PrivateKey");

    // Build the same keys again from their fields
    let _public1 = X25519PublicKey::new(*public.u());
    let _private1 = X25519PrivateKey::new(*private.k());

    // The same for X448
    let pair = algo.key_pair_generator().generate_by_name("X448")?;
    let public = pair.public().as_any().downcast_ref::<X448PublicKey>().expect("an X448PublicKey");
    let private = pair.private().as_any().downcast_ref::<X448PrivateKey>().expect("an X448PrivateKey");
    let _public2 = X448PublicKey::new(*public.u());
    let _private2 = X448PrivateKey::new(*private.k());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `X25519`, `X448` agreements | The other side's key | Its own key |

A key goes only to the row of its own curve; the other curve's key is `InvalidParams`.

## Keys that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| An X25519 key in the X448 row, or the other way round | `init` or `calculate_agreement` | `InvalidParams` |
| The other side's public key of small order | `calculate_agreement` | `InvalidParams`: the secret would be all zeros |
| A public key that is not the one the other side holds the private key of | Only in use | The two sides get different secrets, with no error |

To check that two keys belong together, compare `generate_public_key()` of the private key with the
public key: the public keys are `PartialEq`.

[Key pair generation](../KeyPairGeneration.md) · [X25519 and X448](../X25519.md)
