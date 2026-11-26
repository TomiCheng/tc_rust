# DhPublicKey and DhPrivateKey

Enable the `dh` feature and import `DhPublicKey` and `DhPrivateKey` from `tc_algo::params::key`.
The `DH` key pair generator returns a `DhPublicKey` and a `DhPrivateKey`, each holding a copy of
the group.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | The public value, `g^x mod p` | yes | | `y()` |
| `x` | The private value | | yes | `x()` |
| `params` | The group, a [`DhParameters`](../KeyPairGeneration/DhParameters.md) | yes | yes | `params()` |

`y` and `x` are `&PaddedBigUint`, and `params` a `&DhParameters`. A key is built from the same
fields:

| Build | Gives |
|---|---|
| `DhPublicKey::new(y, params)` | The public key |
| `DhPrivateKey::new(x, params)` | The private key |

The values are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export; values read from
another key, as the example does, need no import.

Nothing is checked when a key is built. `DhPublicKey::validate()` checks that `p` has at most 16384
bits and `y` is in `[2, p - 2]`, and in the subgroup when the group has a `q`; the agreement and
IES rows call it on the other side's key. The private key is not checked, as in Bouncy Castle.
Both keys are `Clone`. The public key is `Debug` and `PartialEq`; the private key is neither, so
that `x` is not printed or compared in variable time, and it wipes `x` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::dh_groups::rfc7919_ffdhe2048;
use tc_algo::params::key::{DhPrivateKey, DhPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let group = rfc7919_ffdhe2048();
    let pair = algo.key_pair_generator().generate_by_name_with("DH", &group)?;

    // The keys of the pair
    let public = pair.public().as_any().downcast_ref::<DhPublicKey>().expect("a DhPublicKey");
    let private = pair.private().as_any().downcast_ref::<DhPrivateKey>().expect("a DhPrivateKey");

    // Build the same keys again from their fields
    let _public1 = DhPublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = DhPrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `DH` agreement | The other side's key | Its own key |
| `IES` cipher | The other side's key, in `IesDhParams` | Its own key, in `IesDhParams` |

## Groups that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| The other side's public key is of another group than this side's private key | The agreement, also inside `IES` | `InvalidParams` |
| The groups differ only in `l`, `m` or `j` | Never | They count as one group, as in Bouncy Castle: equality compares `p`, `g` and `q` alone, and the agreement gives the same secret |
| A key built with the `y` of one group and the `params` of another | The other side's `validate` | `InvalidParams` when `y` is outside `[2, p - 2]` or the subgroup; if it passes, the two sides get different secrets with no error |

So build a key with the `params` its value belongs to, as the example does.

[Key pair generation](../KeyPairGeneration.md) · [Diffie-Hellman](../Dh.md) ·
[DhParameters](../KeyPairGeneration/DhParameters.md)
