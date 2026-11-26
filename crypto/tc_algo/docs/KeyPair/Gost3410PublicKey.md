# Gost3410PublicKey and Gost3410PrivateKey

Enable `gost3410` and import `Gost3410PublicKey` and `Gost3410PrivateKey` from
`tc_algo::params::key`. The `GOST3410` key pair generator returns these types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | Public group value | yes |  | `y()` |
| `x` | Private exponent |  | yes | `x()` |
| `params` | Domain parameters | yes | yes | `params()` |

| Build | Gives |
|---|---|
| `Gost3410PublicKey::new(y, params)` | Public key |
| `Gost3410PrivateKey::new(x, params)` | Private key |

The integers are `PaddedBigUint` from `tc_bigint`. Values read from another key need no import.
The constructors store the fields as supplied. The signer calls `validate()` at initialization
to check the domain and the key value's range. Dropping the private key wipes `x`.
The public key implements `Debug` and `PartialEq`. The private key omits these traits.

## Read and build a key pair

```rust
use tc_algo::params::generate::Gost3410KeyGenParams;
use tc_algo::params::key::{Gost3410PrivateKey, Gost3410PublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = Gost3410KeyGenParams::new(1024);
    let pair = algo.key_pair_generator().generate_by_name_with("GOST3410", &params)?;

    let public = pair.public().as_any().downcast_ref::<Gost3410PublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<Gost3410PrivateKey>().unwrap();

    let _public1 = Gost3410PublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = Gost3410PrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `GOST3410` | Verifies | Signs |

[Key pair generation](../KeyPairGeneration.md) ·
[Gost3410](../Gost3410.md) ·
[Gost3410KeyGenParams](../KeyPairGeneration/Gost3410KeyGenParams.md)
