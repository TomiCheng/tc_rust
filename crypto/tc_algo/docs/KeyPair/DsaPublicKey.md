# DsaPublicKey and DsaPrivateKey

Enable `dsa` and import `DsaPublicKey` and `DsaPrivateKey` from `tc_algo::params::key`. The
`DSA` key pair generator returns these types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | Public group value | yes |  | `y()` |
| `x` | Private exponent |  | yes | `x()` |
| `params` | Domain parameters | yes | yes | `params()` |

| Build | Gives |
|---|---|
| `DsaPublicKey::new(y, params)` | Public key |
| `DsaPrivateKey::new(x, params)` | Private key |

The integers are `PaddedBigUint` from `tc_bigint`. Values read from another key need no import.
The constructors store the fields as supplied. The signer calls `validate()` at initialization.
It checks the domain and the public value's range and subgroup membership, or the private
exponent's range. Dropping the private key wipes `x`.
The public key implements `Debug` and `PartialEq`. The private key omits these traits.

## Read and build a key pair

```rust
use tc_algo::params::generate::DsaKeyGenParams;
use tc_algo::params::key::{DsaPrivateKey, DsaPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = DsaKeyGenParams::new(2048, 256);
    let pair = algo.key_pair_generator().generate_by_name_with("DSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<DsaPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<DsaPrivateKey>().unwrap();

    let _public1 = DsaPublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = DsaPrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `SHA-256withDSA` | Verifies | Signs |

[Key pair generation](../KeyPairGeneration.md) ·
[Dsa](../Dsa.md) ·
[DsaKeyGenParams](../KeyPairGeneration/DsaKeyGenParams.md)
