# ElGamalPublicKey and ElGamalPrivateKey

Enable the `elgamal` feature and import `ElGamalPublicKey` and `ElGamalPrivateKey` from
`tc_algo::params::key`. The `ELGAMAL` key pair generator returns an `ElGamalPublicKey` and an
`ElGamalPrivateKey`, each holding a copy of the group.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | The public value, `g^x mod p` | yes | | `y()` |
| `x` | The private value | | yes | `x()` |
| `params` | The group, an [`ElGamalParameters`](../KeyPairGeneration/ElGamalParameters.md) | yes | yes | `params()` |

`y` and `x` are `&PaddedBigUint`, and `params` an `&ElGamalParameters`. A key is built from the
same fields:

| Build | Gives |
|---|---|
| `ElGamalPublicKey::new(y, params)` | The public key |
| `ElGamalPrivateKey::new(x, params)` | The private key |

The values are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export; values read from
another key, as the example does, need no import.

Nothing is checked when a key is built. The cipher rows check a key at `init`: the group with
`ElGamalParameters::validate`, `y` in `[2, p - 2]` for a public key, which Bouncy Castle does not
check, and `x` not above `p - 2` for a private key. Both keys are `Clone`. The public key is
`Debug` and `PartialEq`; the private key is neither, so that `x` is not printed or compared in
variable time, and it wipes `x` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::elgamal_groups::rfc7919_ffdhe2048;
use tc_algo::params::key::{ElGamalPrivateKey, ElGamalPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let group = rfc7919_ffdhe2048();
    let pair = algo.key_pair_generator().generate_by_name_with("ELGAMAL", &group)?;

    // The keys of the pair
    let public = pair
        .public()
        .as_any()
        .downcast_ref::<ElGamalPublicKey>()
        .expect("an ElGamalPublicKey");
    let private = pair
        .private()
        .as_any()
        .downcast_ref::<ElGamalPrivateKey>()
        .expect("an ElGamalPrivateKey");

    // Build the same keys again from their fields
    let _public1 = ElGamalPublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = ElGamalPrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `ELGAMAL//OAEPWITHSHA256ANDMGF1PADDING` and the other OAEP rows | Encrypts | Decrypts |
| `ELGAMAL//PKCS1PADDING` | Encrypts | Decrypts |
| `ELGAMAL`, with no padding | Encrypts | Decrypts |

[ElGamal](../ElGamal.md#algorithms-1) lists the rows. A public key goes only to encryption and a
private key only to decryption; the other way round is `InvalidParams`.

## Groups that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A ciphertext made with the public key of a group with a `p` of another size | `decrypt` | `DataLength` |
| A ciphertext made with the public key of another group of the same size | `decrypt` | `InvalidCiphertext` with padding; with no padding, `Ok` with a wrong message |
| The groups differ only in `l` | Never | `l` only sets the length of `x` when a key is generated; the keys work together |
| A key built with the value of one group and the `params` of another | `init` when the value is out of range, otherwise `decrypt` | `InvalidParams`; or, if it passes, the ciphertexts do not decrypt, as above |

Unlike a DH agreement, nothing compares the groups of the two keys: a ciphertext does not say which
key made it. So build a key with the `params` its value belongs to, as the example does.

[Key pair generation](../KeyPairGeneration.md) · [ElGamal](../ElGamal.md) ·
[ElGamalParameters](../KeyPairGeneration/ElGamalParameters.md)
