# DhParameters

Enable the `dh` feature to use the `DH` key pair generator. Import `DhParameters` and the
standard groups in `dh_groups` from `tc_algo::params::generate`, and the key types from
`tc_algo::params::key`.

A `DhParameters` is both the input of the generator and part of each key, so
`tc_algo::params::key` exports it and `dh_groups` too. The two paths name the same type.

## Generate a key pair

```rust
use tc_algo::params::generate::DhParameters;
use tc_algo::params::generate::dh_groups::rfc7919_ffdhe2048;
use tc_algo::params::key::{DhPrivateKey, DhPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The group is the input of the generator
    let group: DhParameters = rfc7919_ffdhe2048();
    let pair = algo.key_pair_generator().generate_by_name_with("DH", &group)?;

    let public = pair.public().as_any().downcast_ref::<DhPublicKey>().expect("a DhPublicKey");
    let private = pair.private().as_any().downcast_ref::<DhPrivateKey>().expect("a DhPrivateKey");

    // Each key carries a copy of the group
    let _: &DhParameters = public.params();
    assert_eq!(private.params(), &group);
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is a `DhPublicKey` and whose `private()` is a
`DhPrivateKey`, each inside `Box<dyn Params>` and each holding a copy of the group. Both parties
of an agreement use the same group, which is public.

`DH` has no default group, so `generate_by_name("DH")` returns `NotInitialized`. Any params other
than a `DhParameters` are `InvalidParams`, and so is a group that fails the checks below.

## Standard groups

`dh_groups` has a function for each group of Bouncy Castle's `DHStandardGroups`. Each one is a
safe prime `p` with `g` = 2 and `q` = (`p` - 1) / 2. The private value has the length in the last
column, or is drawn from below `q` where there is none.

| Function | Bits of `p` | Standard | Bits of the private value |
|---|---|---|---|
| `rfc7919_ffdhe2048` | 2048 | RFC 7919 | 225 |
| `rfc7919_ffdhe3072` | 3072 | RFC 7919 | 275 |
| `rfc7919_ffdhe4096` | 4096 | RFC 7919 | 325 |
| `rfc7919_ffdhe6144` | 6144 | RFC 7919 | 375 |
| `rfc7919_ffdhe8192` | 8192 | RFC 7919 | 400 |
| `rfc3526_2048` | 2048 | RFC 3526, group 14 | 225 |
| `rfc3526_3072` | 3072 | RFC 3526, group 15 | 275 |
| `rfc3526_4096` | 4096 | RFC 3526, group 16 | 325 |
| `rfc3526_6144` | 6144 | RFC 3526, group 17 | 375 |
| `rfc3526_8192` | 8192 | RFC 3526, group 18 | 400 |

**Too small to be safe**, and only for working with old systems:

| Function | Bits of `p` | Standard | Bits of the private value |
|---|---|---|---|
| `rfc3526_1536` | 1536 | RFC 3526, group 5 | 200 |
| `rfc2409_1024` | 1024 | RFC 2409, group 2 | |
| `rfc2409_768` | 768 | RFC 2409, group 1 | |
| `rfc4306_1024`, `rfc5996_1024` | 1024 | the same as `rfc2409_1024` | |
| `rfc4306_768`, `rfc5996_768` | 768 | the same as `rfc2409_768` | |

## A group of your own

The numbers are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export.

`algo.params_generator().generate_by_name("DH_GROUP")` generates a new group, 2048 bits without
`init`, or as a `DhGroupGenerationParams` sets. It is slow, and RFC 7919 recommends a named group
such as `rfc7919_ffdhe2048` instead.

| Method | Setting | Default | Valid range |
|---|---|---|---|
| `new(p, g)` | Modulus `p` and generator `g` | none | `p` odd and above 2; `g` in `[2, p - 2]` |
| `with_q(q)` | Subgroup order | none | At least 3, fewer bits than `p` |
| `with_l(l)` | Bit length of the private value | `0` (none) | Below the bits of `p`, not below `m` |
| `with_m(m)` | Least bit length of the private value | 160, or `l` if smaller | Below the bits of `p` |
| `with_j(j)` | Cofactor | none | At least 2 |
| `with_validation(v)` | Data `p` was generated from | none | Not checked |

Nothing is checked when the parameters are built; the generator checks them during `init`.
Whether `p` and `q` are prime is not checked, as in Bouncy Castle, so a group from an untrusted
source is up to the caller.

| Accessor | Returns |
|---|---|
| `p()` | Modulus (`&PaddedBigUint`) |
| `g()` | Generator (`&PaddedBigUint`) |
| `q()` | Subgroup order (`Option<&PaddedBigUint>`) |
| `l()` | Bit length of the private value, `0` when not set (`u32`) |
| `m()` | Least bit length of the private value (`u32`) |
| `j()` | Cofactor (`Option<&PaddedBigUint>`) |
| `validation()` | Generation data (`Option<&DhValidationParameters>`) |

Two `DhParameters` are equal when `p`, `g` and `q` are, as in Bouncy Castle.

[Key pair generation](../KeyPairGeneration.md) · [Diffie-Hellman](../Dh.md)
