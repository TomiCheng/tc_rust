# X25519 and X448 key types

Enable `cfrg-curves`. Import `X25519PublicKey`, `X25519PrivateKey`, `X448PublicKey`,
`X448PrivateKey` from `tc_algo::params::key`. The `X25519` and `X448` generators return their
corresponding key types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `u` | Montgomery u-coordinate bytes | yes |  | `u()` |
| `k` | Private scalar input bytes |  | yes | `k()` |

| Build | Gives |
|---|---|
| `X25519PublicKey::new(u)`, `X448PublicKey::new(u)` | Public key |
| `X25519PrivateKey::new(k)`, `X448PrivateKey::new(k)` | Private key |

Constructors store fixed arrays as supplied. Both keys use 32 bytes for `X25519` and 56 bytes
for `X448`. The private key derives the corresponding public key through `generate_public_key()`
and wipes `k` on drop.
Agreement rejects an all-zero shared result.
The public keys implement `Debug` and `PartialEq`. The private keys omit those traits.

## Read and build a key pair

```rust
use tc_algo::params::key::{
    X25519PublicKey, X25519PrivateKey, X448PublicKey, X448PrivateKey,
};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let pair = algo.key_pair_generator().generate_by_name("X25519")?;
    let public = pair.public().as_any().downcast_ref::<X25519PublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<X25519PrivateKey>().unwrap();
    let _public1 = X25519PublicKey::new(*public.u());
    let _private1 = X25519PrivateKey::new(*private.k());

    let pair = algo.key_pair_generator().generate_by_name("X448")?;
    let public = pair.public().as_any().downcast_ref::<X448PublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<X448PrivateKey>().unwrap();
    let _public2 = X448PublicKey::new(*public.u());
    let _private2 = X448PrivateKey::new(*private.k());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `X25519`, `X448` | Peer key | Local key |

[Key pair generation](../KeyPairGeneration.md) ·
[X25519](../X25519.md)
