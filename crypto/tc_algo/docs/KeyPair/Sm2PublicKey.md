# Sm2PublicKey and Sm2PrivateKey

Enable `sm2` and import `Sm2PublicKey` and `Sm2PrivateKey` from `tc_algo::params::key`. The
`SM2` generator returns these aliases of the EC key types on sm2p256v1.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `g` | Base point carrying the curve | yes | yes | `g()` |
| `q` | Public point | yes |  | `q()` |
| `d` | Private scalar |  | yes | `d()` |

| Build | Gives |
|---|---|
| `Sm2PublicKey::new(g, &q)` | Public key or `InvalidPublicPoint` |
| `Sm2PrivateKey::new(g, d)` | Private key, `MissingOrder`, or `InvalidPrivateScalar` |

The points and `PaddedBigUint` scalar can be read from another key without importing their
types.
The public constructor imports the point onto the base point's curve and rejects infinity or a
point outside the subgroup. The private constructor requires the curve order and checks the
scalar's range. Dropping the private key wipes the scalar. Both keys omit `Debug` and
`PartialEq`.

## Read and build a key pair

```rust
use tc_algo::params::key::{Sm2PrivateKey, Sm2PublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let pair = algo.key_pair_generator().generate_by_name("SM2")?;

    let public = pair.public().as_any().downcast_ref::<Sm2PublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<Sm2PrivateKey>().unwrap();

    let _public1 = Sm2PublicKey::new(public.g().clone(), public.q())?;
    let _private1 = Sm2PrivateKey::new(private.g().clone(), private.d().clone())?;
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `SM2`, `SM2//C1C3C2` | Encrypts | Decrypts |
| `SM3withSM2`, `SHA256withSM2` | Verifies | Signs |

[Key pair generation](../KeyPairGeneration.md) ·
[Sm2](../Sm2.md)
