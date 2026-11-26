# Ed25519 and Ed448 keys

Enable the `cfrg-curves` feature and import `Ed25519PublicKey`, `Ed25519PrivateKey`,
`Ed448PublicKey` and `Ed448PrivateKey` from `tc_algo::params::key`. The `Ed25519` and `Ed448` key
pair generators return them. The keys are the byte strings of RFC 8032, so each holds one fixed
array.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `a` | The encoded public point `A` | yes | | `a()` |
| `k` | The private key, the random bytes the signing scalar is hashed from | | yes | `k()` |

| Key | Bytes of `a` and `k` |
|---|---|
| Ed25519 | 32 (`&[u8; 32]`) |
| Ed448 | 57 (`&[u8; 57]`) |

The private key also gives its public key with `generate_public_key()`. A key is built from the
same fields:

| Build | Gives |
|---|---|
| `Ed25519PublicKey::new(a)`, `Ed448PublicKey::new(a)` | The public key |
| `Ed25519PrivateKey::new(k)`, `Ed448PrivateKey::new(k)` | The private key |

Nothing is checked when a key is built; the arrays fix the lengths. A verifier checks at `init`
that `a` decodes to a point of the curve, the partial check of RFC 8032, and turns it down as
`InvalidParams` otherwise. Any `k` is a valid private key. All four keys are `Clone`. The public
keys are `Debug` and `PartialEq`; the private keys are neither, and they wipe `k` when they are
dropped.

## Read and build a key pair

```rust
use tc_algo::params::key::{Ed25519PrivateKey, Ed25519PublicKey, Ed448PrivateKey, Ed448PublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The curve is fixed, so Ed25519 and Ed448 take no params
    let pair = algo.key_pair_generator().generate_by_name("Ed25519")?;
    let public = pair.public().as_any().downcast_ref::<Ed25519PublicKey>().expect("an Ed25519PublicKey");
    let private = pair.private().as_any().downcast_ref::<Ed25519PrivateKey>().expect("an Ed25519PrivateKey");

    // Build the same keys again from their fields
    let _public1 = Ed25519PublicKey::new(*public.a());
    let _private1 = Ed25519PrivateKey::new(*private.k());

    // The same for Ed448
    let pair = algo.key_pair_generator().generate_by_name("Ed448")?;
    let public = pair.public().as_any().downcast_ref::<Ed448PublicKey>().expect("an Ed448PublicKey");
    let private = pair.private().as_any().downcast_ref::<Ed448PrivateKey>().expect("an Ed448PrivateKey");
    let _public2 = Ed448PublicKey::new(*public.a());
    let _private2 = Ed448PrivateKey::new(*private.k());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `Ed25519`, `Ed25519ctx`, `Ed25519ph` | Verifies | Signs |
| `Ed448`, `Ed448ph` | Verifies | Signs |

A key goes only to the rows of its own curve; the other curve's key is `InvalidParams`, as is a
public key where a private key goes, or the other way round.

## Keys that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| An Ed25519 key in an Ed448 row, or the other way round | `init` | `InvalidParams` |
| An `a` that does not decode to a point of the curve | `init` of the verifier | `InvalidParams` |
| A public key that is not the one of the private key | Only in use | `verify` gives `false` |

To check that two keys belong together, compare `generate_public_key()` of the private key with the
public key: the public keys are `PartialEq`.

[Key pair generation](../KeyPairGeneration.md) · [EdDSA](../EdDSA.md)
