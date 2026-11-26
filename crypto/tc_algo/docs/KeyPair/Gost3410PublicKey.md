# Gost3410PublicKey and Gost3410PrivateKey

Enable the `gost3410` feature and import `Gost3410PublicKey` and `Gost3410PrivateKey` from
`tc_algo::params::key`. The `GOST3410` key pair generator returns a `Gost3410PublicKey` and a
`Gost3410PrivateKey` of GOST R 34.10-94, each holding a copy of the domain.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | The public value, `a^x mod p` | yes | | `y()` |
| `x` | The private value | | yes | `x()` |
| `params` | The domain, a [`Gost3410Parameters`](../KeyPairGeneration/Gost3410KeyGenParams.md#a-domain-in-hand) | yes | yes | `params()` |

`y` and `x` are `&PaddedBigUint`, and `params` a `&Gost3410Parameters`. A key is built from the
same fields:

| Build | Gives |
|---|---|
| `Gost3410PublicKey::new(y, params)` | The public key |
| `Gost3410PrivateKey::new(x, params)` | The private key |

The values are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export; values read from
another key, as the example does, need no import.

Nothing is checked when a key is built. The signer row calls the key's `validate()` at `init`, the
checks of Bouncy Castle's constructors: the domain passes its checks, and `y` is in `[1, p - 1]`
for a public key, or `x` is in `[1, q - 1]` and at most 256 bits for a private key. Unlike DSA, `y`
is not checked to be in the subgroup. Both keys are `Clone`. The public key is `Debug` and
`PartialEq`; the private key is neither, so that `x` is not printed or compared in variable time,
and it wipes `x` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::Gost3410KeyGenParams;
use tc_algo::params::key::{Gost3410PrivateKey, Gost3410PublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = Gost3410KeyGenParams::new(1024);
    let pair = algo.key_pair_generator().generate_by_name_with("GOST3410", &params)?;

    // The keys of the pair
    let public = pair
        .public()
        .as_any()
        .downcast_ref::<Gost3410PublicKey>()
        .expect("a Gost3410PublicKey");
    let private = pair
        .private()
        .as_any()
        .downcast_ref::<Gost3410PrivateKey>()
        .expect("a Gost3410PrivateKey");

    // Build the same keys again from their fields
    let _public1 = Gost3410PublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = Gost3410PrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `GOST3410`, also `GOST3411withGOST3410` | Verifies | Signs |

A public key goes only to verifying and a private key only to signing; the other way round is
`InvalidParams`.

## Domains that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A public key built with the `y` of one domain and the `params` of another | `init` when `y` is not below `p`, otherwise in use | `InvalidParams`; or, as the subgroup is not checked, `verify` gives `false` |
| A private key built with the `x` of one domain and the `params` of another | `init` when `x` is not below `q`, otherwise in use | `InvalidParams`; or its signatures do not verify |
| A signature verified with a public key of another domain, or of another pair | Only in use | `verify` gives `false` |

Nothing compares the domains of the two keys, so build a key with the `params` its value belongs
to, as the example does.

[Key pair generation](../KeyPairGeneration.md) · [GOST R 34.10-94](../Gost3410.md) ·
[Gost3410KeyGenParams](../KeyPairGeneration/Gost3410KeyGenParams.md)
