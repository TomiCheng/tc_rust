# Ed25519 and Ed448 key types

Enable `cfrg-curves`. Import `Ed25519PublicKey`, `Ed25519PrivateKey`, `Ed448PublicKey`,
`Ed448PrivateKey` from `tc_algo::params::key`. The `Ed25519` and `Ed448` generators return their
corresponding key types.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `a` | Public point bytes | yes |  | `a()` |
| `k` | Private seed bytes |  | yes | `k()` |

| Build | Gives |
|---|---|
| `Ed25519PublicKey::new(a)`, `Ed448PublicKey::new(a)` | Public key |
| `Ed25519PrivateKey::new(k)`, `Ed448PrivateKey::new(k)` | Private key |

Constructors store fixed arrays as supplied. Both keys use 32 bytes for `Ed25519` and 57 bytes
for `Ed448`. The private key derives the corresponding public key through
`generate_public_key()` and wipes `k` on drop.
The signer partially validates the public point when initialized for verification.
The public keys implement `Debug` and `PartialEq`. The private keys omit those traits.

## Read and build a key pair

```rust
use tc_algo::params::key::{
    Ed25519PublicKey, Ed25519PrivateKey, Ed448PublicKey, Ed448PrivateKey,
};
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let algo = DefaultAlgoBuilder::default().build();
    let pair = algo.key_pair_generator().generate_by_name("Ed25519")?;
    let public = pair.public().as_any().downcast_ref::<Ed25519PublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<Ed25519PrivateKey>().unwrap();
    let _public1 = Ed25519PublicKey::new(*public.a());
    let _private1 = Ed25519PrivateKey::new(*private.k());

    let pair = algo.key_pair_generator().generate_by_name("Ed448")?;
    let public = pair.public().as_any().downcast_ref::<Ed448PublicKey>().unwrap();
    let private = pair.private().as_any().downcast_ref::<Ed448PrivateKey>().unwrap();
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

[Key pair generation](../KeyPairGeneration.md) ·
[EdDSA](../EdDSA.md)
