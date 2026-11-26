# ElGamalPublicKey and ElGamalPrivateKey

Enable `elgamal` and import `ElGamalPublicKey` and `ElGamalPrivateKey` from
`tc_algo::params::key`. The `ELGAMAL` key pair generator returns these types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | Public group value | yes |  | `y()` |
| `x` | Private exponent |  | yes | `x()` |
| `params` | Domain parameters | yes | yes | `params()` |

| Build | Gives |
|---|---|
| `ElGamalPublicKey::new(y, params)` | Public key |
| `ElGamalPrivateKey::new(x, params)` | Private key |

The integers are `PaddedBigUint` from `tc_bigint`. Values read from another key need no import.
The constructors store the fields as supplied. The cipher checks the group and key value during
initialization. Dropping the private key wipes `x`.
The public key implements `Debug` and `PartialEq`. The private key omits these traits.

## Read and build a key pair

```rust
use tc_algo::params::generate::elgamal_groups::rfc7919_ffdhe2048;
use tc_algo::params::key::{ElGamalPrivateKey, ElGamalPublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = rfc7919_ffdhe2048();
    let pair = algo.key_pair_generator().generate_by_name_with("ELGAMAL", &params)?;

    let public = pair.public().as_any().downcast_ref::<ElGamalPublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<ElGamalPrivateKey>().unwrap();

    let _public1 = ElGamalPublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = ElGamalPrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING` | Encrypts | Decrypts |
| `ELGAMAL`, `ELGAMAL//OAEPPADDING`, `ELGAMAL//PKCS1PADDING` | Encrypts | Decrypts |

[Key pair generation](../KeyPairGeneration.md) ·
[ElGamal](../ElGamal.md) ·
[ElGamalParameters](../KeyPairGeneration/ElGamalParameters.md)
