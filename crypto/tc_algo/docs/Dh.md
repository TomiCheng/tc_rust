# Diffie-Hellman

Two parties that share only a public group each make a key pair and send each other the public key.
Each then combines its own private key with the other's public key, and both arrive at one secret
that nobody watching can calculate.

The `dh` feature of `tc_algo` has the rows.

## Key pairs

The group is public, and both parties use the same one:

```rust
use tc_algo::params::dh_groups::rfc3526_2048;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let group = rfc3526_2048();

    // One pair for each party
    let _alice = algo.key_pair_generator().generate_by_name_with("DH", &group)?;
    let _bob = algo.key_pair_generator().generate_by_name_with("DH", &group)?;

    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params |
|---|---|---|---|
| `DH` | none | `dh` | `DhParameters` |

`DIFFIEHELLMAN` finds it too, and the case of a name does not matter.

### Using it

- The row takes a `DhParameters`, and any other type is `InvalidParams`, as is a bad group. There is
  no default group, so `generate_by_name` and `generate_by_oid`, which do not call `init`, give
  `NotInitialized`.
- The public key is a `DhPublicKey` and the private key a `DhPrivateKey`, in `tc_algo::params`. The
  private key wipes its private value when dropped, and has no `Debug` or `==`.
- The keys draw from the source of `DefaultAlgoBuilder::set_rand`, which by default is the operating
  system's.

### Standard groups

`tc_algo::params::dh_groups` has a function for each group of Bouncy Castle's `DHStandardGroups`.
Each one is a safe prime `p` with `g` = 2. The private value has the length in the last column, or
is drawn from below `q` where there is none.

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

## Agreement

From two key pairs to one shared secret. The keys of a pair go straight in as params:

```rust
use tc_algo::params::dh_groups::rfc3526_2048;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let group = rfc3526_2048();

    // Generate a pair for each party
    let alice = algo.key_pair_generator().generate_by_name_with("DH", &group)?;
    let bob = algo.key_pair_generator().generate_by_name_with("DH", &group)?;

    // Alice's private key with Bob's public key
    let mut agreement = algo.agreement().get_by_name("DH")?;
    agreement.init(alice.private())?;
    let mut alice_secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(bob.public(), &mut alice_secret)?;

    // Bob's private key with Alice's public key gives the same secret
    let mut agreement = algo.agreement().get_by_name("DH")?;
    agreement.init(bob.private())?;
    let mut bob_secret = vec![0; agreement.agreement_size()];
    agreement.calculate_agreement(alice.public(), &mut bob_secret)?;

    assert_eq!(alice_secret, bob_secret);
    Ok(())
}
```

### Algorithms

| Name | OID | Feature | Params | Other side's key |
|---|---|---|---|---|
| `DH` | none | `dh` | `DhPrivateKey` | `DhPublicKey` |

`DIFFIEHELLMAN` finds it too, and the case of a name does not matter. Both key types are in
`tc_algo::params`. Any other type is `InvalidParams`.

### Using it

- **The secret is not yet a key.** Its bytes are not uniformly random, so put them through a KDF
  before using them.
- **DH alone does not say who is on the other side.** Someone in the middle can run an agreement with
  each party, so authenticate the public keys, for instance with a signature.
- `calculate_agreement` writes the secret into a buffer of `agreement_size` bytes, as the
  `Agreement` of `tc_agreement` does. Its length is that of `p`, with zeros in front where needed,
  whereas Bouncy Castle gives an integer that loses them. The buffer is the caller's, and so is
  wiping it when the secret is done with, for instance with `tc_zeroize`.
- It refuses a public key of another group, one outside `[2, p - 2]`, one outside the subgroup when
  the group has a `q`, and a secret of 1, all as `InvalidParams`.
- It gives `NotInitialized` before an `init` that succeeded.
- The power is constant time with respect to the private key. Whether a secret is 1 is compared in
  constant time, and shows only in the error.
