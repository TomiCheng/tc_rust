# DhPublicKey and DhPrivateKey

Enable `dh` and import `DhPublicKey` and `DhPrivateKey` from `tc_algo::params::key`. The `DH`
key pair generator returns these types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | Public group value | yes |  | `y()` |
| `x` | Private exponent |  | yes | `x()` |
| `params` | Domain parameters | yes | yes | `params()` |

| Build | Gives |
|---|---|
| `DhPublicKey::new(y, params)` | Public key |
| `DhPrivateKey::new(x, params)` | Private key |

The integers are `PaddedBigUint` from `tc_bigint`. Values read from another key need no import.
The constructors store the fields as supplied. Agreement validates the peer's public value,
including subgroup membership when the group supplies an order. The private key has no
validation method. Dropping the private key wipes `x`.
The public key implements `Debug` and `PartialEq`. The private key omits these traits.

## Read and build a key pair

```rust
use tc_algo::params::generate::dh_groups::rfc7919_ffdhe2048;
use tc_algo::params::key::{DhPrivateKey, DhPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = rfc7919_ffdhe2048();
    let pair = algo.key_pair_generator().generate_by_name_with("DH", &params)?;

    let public = pair.public().as_any().downcast_ref::<DhPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<DhPrivateKey>().unwrap();

    let _public1 = DhPublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = DhPrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `DH` | Peer key | Local key |

[Key pair generation](../KeyPairGeneration.md) ·
[Dh](../Dh.md) ·
[DhParameters](../KeyPairGeneration/DhParameters.md)
