# DsaPublicKey and DsaPrivateKey

Enable the `dsa` feature and import `DsaPublicKey` and `DsaPrivateKey` from `tc_algo::params::key`.
The `DSA` key pair generator returns a `DsaPublicKey` and a `DsaPrivateKey`, each holding a copy of
the domain.

## Fields

| Field | What it is | Public key | Private key | Accessor |
|---|---|---|---|---|
| `y` | The public value, `g^x mod p` | yes | | `y()` |
| `x` | The private value | | yes | `x()` |
| `params` | The domain, a [`DsaParameters`](../KeyPairGeneration/DsaKeyGenParams.md#a-domain-in-hand) | yes | yes | `params()` |

`y` and `x` are `&PaddedBigUint`, and `params` a `&DsaParameters`. A key is built from the same
fields:

| Build | Gives |
|---|---|
| `DsaPublicKey::new(y, params)` | The public key |
| `DsaPrivateKey::new(x, params)` | The private key |

The values are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export; values read from
another key, as the example does, need no import.

Nothing is checked when a key is built. The signer rows call the key's `validate()` at `init`: the
domain passes its checks, and `y` is in `[2, p - 2]` with `y^q = 1 mod p` for a public key, or `x`
is in `[1, q - 1]` for a private key, which Bouncy Castle does not check. Both keys are `Clone`. The
public key is `Debug` and `PartialEq`; the private key is neither, so that `x` is not printed or
compared in variable time, and it wipes `x` when it is dropped.

## Read and build a key pair

```rust
use tc_algo::params::generate::DsaKeyGenParams;
use tc_algo::params::key::{DsaPrivateKey, DsaPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let params = DsaKeyGenParams::new(2048, 256);
    let pair = algo.key_pair_generator().generate_by_name_with("DSA", &params)?;

    // The keys of the pair
    let public = pair.public().as_any().downcast_ref::<DsaPublicKey>().expect("a DsaPublicKey");
    let private = pair.private().as_any().downcast_ref::<DsaPrivateKey>().expect("a DsaPrivateKey");

    // Build the same keys again from their fields
    let _public1 = DsaPublicKey::new(public.y().clone(), public.params().clone());
    let _private1 = DsaPrivateKey::new(private.x().clone(), private.params().clone());
    Ok(())
}
```

## Use it with an algorithm

| Rows | Public key | Private key |
|---|---|---|
| `SHA-256withDSA` and the other `<DIGEST>withDSA` rows | Verifies | Signs |
| `NONEwithDSA`, which signs a hash made elsewhere | Verifies | Signs |

[DSA](../Dsa.md#algorithms-1) lists the rows. A public key goes only to verifying and a private
key only to signing; the other way round is `InvalidParams`.

## Domains that do not match

| Mismatch | When it shows | What happens |
|---|---|---|
| A public key built with the `y` of one domain and the `params` of another | `init` of the verifier | `InvalidParams`: `y^q` is not 1 |
| A private key built with the `x` of one domain and the `params` of another | `init` when `x` is not below `q`, otherwise in use | `InvalidParams`; or its signatures do not verify |
| A signature verified with a public key of another domain, or of another pair | Only in use | `verify` gives `false` |

Nothing compares the domains of the two keys, so build a key with the `params` its value belongs
to, as the example does.

[Key pair generation](../KeyPairGeneration.md) · [DSA](../Dsa.md) ·
[DsaKeyGenParams](../KeyPairGeneration/DsaKeyGenParams.md)
