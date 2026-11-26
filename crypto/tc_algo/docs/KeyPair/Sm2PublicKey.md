# Sm2PublicKey and Sm2PrivateKey

Enable the `sm2` feature and import `Sm2PublicKey` and `Sm2PrivateKey` from
`tc_algo::params::key`. The `SM2` key pair generator returns them. They are not types of their
own: `Sm2PublicKey` is `EcPublicKey` and `Sm2PrivateKey` is `EcPrivateKey` on sm2p256v1, the
curve of GM/T 0003, so they are the same types as `EcSm2p256v1PublicKey` and
`EcSm2p256v1PrivateKey`, and a pair the `EC` generator makes on `sm2p256v1` goes to the SM2 rows
as well. [EC keys](EcPublicKey.md) has the rest of what holds for them.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `g` | The base point of sm2p256v1 | yes | yes | `g()` |
| `q` | The public point | yes | | `q()` |
| `d` | The private scalar | | yes | `d()` |

`g` and `q` are points of sm2p256v1, and `d` a `&PaddedBigUint`. A key is built from the same
fields:

| Build | Gives |
|---|---|
| `Sm2PublicKey::new(g, &q)` | The public key, or `InvalidPublicPoint` |
| `Sm2PrivateKey::new(g, d)` | The private key, or `MissingOrder` or `InvalidPrivateScalar` |

The points and the scalar read from another key, as the example does, need no import.
`Sm2PublicKey::new` moves `q` onto the curve of `g` and turns it down when it is infinity or not a
point of the subgroup; `Sm2PrivateKey::new` checks that `d` is in `[1, n - 1]`. Both keys are
`Clone`, with no `Debug` or `PartialEq`, and the private key wipes `d` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::key::{Sm2PrivateKey, Sm2PublicKey};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();

    // The curve is fixed, so SM2 takes no params
    let pair = algo.key_pair_generator().generate_by_name("SM2")?;

    // The keys of the pair
    let public = pair.public().as_any().downcast_ref::<Sm2PublicKey>().expect("an Sm2PublicKey");
    let private = pair.private().as_any().downcast_ref::<Sm2PrivateKey>().expect("an Sm2PrivateKey");

    // Build the same keys again from their fields
    let _public1 = Sm2PublicKey::new(public.g().clone(), public.q())?;
    let _private1 = Sm2PrivateKey::new(private.g().clone(), private.d().clone())?;
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `SM2`, `SM2//C1C3C2` ciphers | Encrypts | Decrypts |
| `SM3withSM2`, `SHA256withSM2` signers | Verifies | Signs |

The signers use the default user ID of GM/T 0003, `1234567812345678`. A key of another curve is
`InvalidParams`, and a public key where a private key goes, or the other way round, too.

[Key pair generation](../KeyPairGeneration.md) · [SM2](../Sm2.md) · [EC keys](EcPublicKey.md)
