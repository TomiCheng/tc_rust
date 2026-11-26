# DsaKeyGenParams

Enable the `dsa` feature to use the `DSA` key pair generator. Import `DsaKeyGenParams` and
`DsaParameters` from `tc_algo::params::generate`, and the key types from `tc_algo::params::key`.

The `DSA` row takes either of two params:

- a `DsaKeyGenParams`, to generate a new domain of FIPS 186-3 during `init`;
- a `DsaParameters`, a domain already in hand, to make more pairs over it.

A `DsaParameters` is both an input of the generator and part of each key, so
`tc_algo::params::key` exports it too. The two paths name the same type.

## Generate a key pair

```rust
use tc_algo::params::generate::{DsaKeyGenParams, DsaParameters};
use tc_algo::params::key::{DsaPrivateKey, DsaPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A new domain of p of 2048 bits and q of 256, then a pair over it
    let params = DsaKeyGenParams::new(2048, 256);
    let pair = algo.key_pair_generator().generate_by_name_with("DSA", &params)?;

    let public = pair.public().as_any().downcast_ref::<DsaPublicKey>().expect("a DsaPublicKey");
    let private = pair.private().as_any().downcast_ref::<DsaPrivateKey>().expect("a DsaPrivateKey");
    assert_eq!(public.params(), private.params());

    // Each key carries the domain, which makes more pairs without generating it again
    let domain: &DsaParameters = public.params();
    let other = algo.key_pair_generator().generate_by_name_with("DSA", domain)?;
    let other_public = other.public().as_any().downcast_ref::<DsaPublicKey>().expect("a DsaPublicKey");
    let other_private = other.private().as_any().downcast_ref::<DsaPrivateKey>().expect("a DsaPrivateKey");
    assert_eq!(other_public.params(), domain);
    assert_eq!(other_private.params(), domain);
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is a `DsaPublicKey` and whose `private()` is a
`DsaPrivateKey`, each inside `Box<dyn Params>` and each holding a copy of the domain. The domain
and the keys draw from the source of `DefaultAlgoBuilder::set_rand`.

`DSA` has no default, so `generate_by_name("DSA")` returns `NotInitialized`. Any params other than
these two are `InvalidParams`.

FIPS 186-5 no longer approves DSA for new signatures; it is here for old data and for keys that
are already in use.

## Settings

| Method | Setting | Default | Valid range |
|---|---|---|---|
| `new(l, n)` | Bits of `p` and of `q` | none | One of the pairs below |
| `with_certainty(certainty)` | Prime test certainty | `80`, as in Bouncy Castle | At least 1 |

| `l` | `n` | Security strength in bits | Note |
|---|---|---|---|
| 1024 | 160 | 80 | Too small to be safe |
| 2048 | 224 | 112 | |
| 2048 | 256 | 112 | |
| 3072 | 256 | 128 | |

The domain is generated over SHA-256, as FIPS 186-3 has it. Nothing is checked when the params are
built; `init` generates the domain, and returns `InvalidParams` for values outside these ranges.
Generating a domain takes a while, so `init` once and `generate` as many pairs as needed, or keep
the domain and pass it as a `DsaParameters`.

| Accessor | Returns |
|---|---|
| `l()` | Bits of `p` (`u32`) |
| `n()` | Bits of `q` (`u32`) |
| `certainty()` | Prime test certainty (`u32`) |

## A domain in hand

A `DsaParameters` comes from a key, as `public.params()` gives it, or from elsewhere with
`DsaParameters::new(p, q, g)`. The numbers are `PaddedBigUint` of `tc_bigint`, which `tc_algo`
does not re-export. A domain is not checked when it is built, nor at `init`; `generate` checks
that `p` and `q` are odd and above 2, `q` is below `p`, `g` is in `[2, p - 1]` and `p` has at
most 16384 bits, and returns `InvalidParams` otherwise. Whether `p` and `q` are prime is not
checked, so a domain from an untrusted source is up to the caller.

| Accessor | Returns |
|---|---|
| `p()` | Modulus (`&PaddedBigUint`) |
| `q()` | Order of the subgroup (`&PaddedBigUint`) |
| `g()` | Generator (`&PaddedBigUint`) |
| `validation()` | The seed and counter the domain was generated from (`Option<&DsaValidationParameters>`) |

[Key pair generation](../KeyPairGeneration.md) · [DSA](../Dsa.md)
