# ElGamalParameters

Enable the `elgamal` feature to use the `ELGAMAL` key pair generator. Import `ElGamalParameters`
and the standard groups in `elgamal_groups` from `tc_algo::params::generate`, and the key types
from `tc_algo::params::key`.

An `ElGamalParameters` is both the input of the generator and part of each key, so
`tc_algo::params::key` exports it and `elgamal_groups` too. The two paths name the same type.

## Generate a key pair

```rust
use tc_algo::params::generate::ElGamalParameters;
use tc_algo::params::generate::elgamal_groups::rfc7919_ffdhe2048;
use tc_algo::params::key::{ElGamalPrivateKey, ElGamalPublicKey};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The group is the input of the generator
    let group: ElGamalParameters = rfc7919_ffdhe2048();
    let pair = algo.key_pair_generator().generate_by_name_with("ELGAMAL", &group)?;

    let public = pair.public().as_any().downcast_ref::<ElGamalPublicKey>().expect("an ElGamalPublicKey");
    let private = pair.private().as_any().downcast_ref::<ElGamalPrivateKey>().expect("an ElGamalPrivateKey");

    // Each key carries a copy of the group
    let _: &ElGamalParameters = public.params();
    assert_eq!(private.params(), &group);
    Ok(())
}
```

The generator returns a `KeyPair` whose `public()` is an `ElGamalPublicKey` and whose `private()`
is an `ElGamalPrivateKey`, each inside `Box<dyn Params>` and each holding a copy of the group.
Both sides of a message use keys of the same group.

`ELGAMAL` has no default group, so `generate_by_name("ELGAMAL")` returns `NotInitialized`. Any
params other than an `ElGamalParameters` are `InvalidParams`, and so is a group that fails the
checks below.

## Standard groups

These groups are defined by RFCs for Diffie-Hellman: RFC 2409 and RFC 3526 for IKE, RFC 7919 for
TLS. ElGamal works in the same kind of group, a prime `p` with a generator `g`, so they serve it
too and save generating a group. Each function of `elgamal_groups` gives the group of the same
name in `dh_groups` as an `ElGamalParameters`, with its private value length. Each group is a safe
prime `p` with `g` = 2. The private value has the length in the last column, or is drawn from all
of `[2, p - 2]` where there is none.

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

| Method | Setting | Default | Valid range |
|---|---|---|---|
| `new(p, g)` | Modulus `p` and generator `g` | none | `p` odd and above 2; `g` in `[2, p - 2]` |
| `with_l(l)` | Bit length of the private value | `0` (none) | Below the bits of `p` |

The numbers are `PaddedBigUint` of `tc_bigint`, which `tc_algo` does not re-export. Nothing is
checked when the parameters are built; the generator checks them during `init`. Whether `p` is
prime is not checked, as in Bouncy Castle, so a group from an untrusted source is up to the
caller.

`tc_algo` does not generate new groups. To generate one, use `ElGamalGroupGenerator` of
`tc_elgamal`; it is slow, and a standard group serves instead.

| Accessor | Returns |
|---|---|
| `p()` | Modulus (`&PaddedBigUint`) |
| `g()` | Generator (`&PaddedBigUint`) |
| `l()` | Bit length of the private value, `0` when not set (`u32`) |

Two `ElGamalParameters` are equal when `p`, `g` and `l` are, as in Bouncy Castle.

[Key pair generation](../KeyPairGeneration.md) · [ElGamal](../ElGamal.md)
