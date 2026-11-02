# Diffie-Hellman

Diffie-Hellman lets two parties agree on a shared secret over an open channel: each
makes a key pair in the same group, they swap public keys, and each combines its own
private key with the other's public key. Both get the same secret; someone who saw
only the public keys does not.

In `tc_algo` this takes two factories: `generate::key_pair` makes the key pairs
and `agreement` calculates the secret, after Bouncy Castle's `GeneratorUtilities` and
`AgreementUtilities`. Both know DH by the name `"DH"`.

## Enabling DH

DH comes with the `dh` feature, which is in the default features. The groups come
from `tc_dh_key`, the crate that holds the DH keys of `tc_algo`, so add it as well,
at the version `tc_algo` uses.

```toml
[dependencies]
tc_algo = "0.1"
tc_dh_key = "0.1"
```

## Usage

### Both parties, step by step

```rust
use tc_algo::AlgoError;
use tc_algo::agreement;
use tc_algo::generate;
use tc_dh_key::standard_groups::rfc7919_ffdhe2048;

fn main() -> Result<(), AlgoError> {
    // 1. Both parties take the same group, here ffdhe2048 of RFC 7919
    let mut generator = generate::key_pair::get_by_name("DH")?;
    generator.init(rfc7919_ffdhe2048())?;

    // 2. Each makes a key pair and sends the public key to the other
    let alice = generator.generate()?;
    let bob = generator.generate()?;

    // 3. Alice combines her private key with Bob's public key ...
    let mut agreement = agreement::get_by_name("DH")?;
    agreement.init(&alice.private.into())?;
    let alice_secret = agreement.calculate(&bob.public.into())?;

    // ... and Bob combines his with Alice's, for the same secret
    let mut agreement = agreement::get_by_name("DH")?;
    agreement.init(&bob.private.into())?;
    let bob_secret = agreement.calculate(&alice.public.into())?;

    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
```

`init` takes this party's private key in an `AnyAgreementParams`, and `calculate`
takes the other party's public key in an `AgreementPeer`. `.into()` makes either from
the key alone: the params from an `AnyPrivateKey`, the peer from an `AnyPublicKey`.
`AnyAgreementParams::new` and `AgreementPeer::new` are for the agreements that take
more than a key. One agreement calculates as many secrets as you like with the key it
was initialized with.

### In one step

`agreement::calculate` finds the agreement, initializes it and calculates.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement;
use tc_algo::generate;
use tc_dh_key::standard_groups::rfc7919_ffdhe2048;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("DH")?;
    generator.init(rfc7919_ffdhe2048())?;
    let (alice, bob) = (generator.generate()?, generator.generate()?);

    let secret = agreement::calculate("DH", &alice.private.into(), &bob.public.into())?;
    Ok(())
}
```

### In the other party's group

When the other party chose the group, its public key carries it. Make your key pair
in that group, then answer with your public key.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement;
use tc_algo::generate;
use tc_algo::params::AnyPublicKey;
use tc_dh_key::standard_groups::rfc3526_3072;

fn main() -> Result<(), AlgoError> {
    // The other party's public key, in a group it chose
    let mut theirs = generate::key_pair::get_by_name("DH")?;
    theirs.init(rfc3526_3072())?;
    let their_public = theirs.generate()?.public;

    // The group travels with their public key
    let AnyPublicKey::Dh(their_key) = &their_public else {
        panic!("not a DH key");
    };
    let mut generator = generate::key_pair::get_by_name("DH")?;
    generator.init(their_key.params().clone())?;
    let mine = generator.generate()?;

    let secret = agreement::calculate("DH", &mine.private.into(), &their_public.into())?;
    // Send mine.public back to them
    Ok(())
}
```

### The secret is not yet a key

The secret is `g^(xy) mod p`, as many bytes as p has, with leading zeros. Its bytes are
not uniformly random, so do not use them as a key: derive the key from them with a
KDF, such as HKDF, and give the KDF what both parties agree to bind the key to.

So the secret is a `SharedSecret`, not a `SecretKey`, and cannot go to a cipher as
it is. `as_bytes` gives its bytes to the KDF, and they are wiped when it is dropped.
It cannot be cloned, which keeps one copy of it, nor compared with `==`, which would
take time that depends on its bytes.

### Into a buffer of your own

`AnyAgreement` also implements the `Agreement` and `AgreementInit` traits, which
`tc_algo::agreement` re-exports, so it fits generic code. `calculate_agreement`
writes the secret into the first `agreement_size` bytes of a buffer.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, Agreement};
use tc_algo::generate;
use tc_dh_key::standard_groups::rfc7919_ffdhe2048;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("DH")?;
    generator.init(rfc7919_ffdhe2048())?;
    let (alice, bob) = (generator.generate()?, generator.generate()?);

    let mut agreement = agreement::get_by_name("DH")?;
    agreement.init(&alice.private.into())?;
    let mut secret = vec![0; agreement.agreement_size()]; // 256 bytes
    agreement.calculate_agreement(&bob.public.into(), &mut secret)?;
    Ok(())
}
```

`agreement_size` panics before a successful `init`; `calculate` returns
`NotInitialized` instead.

### When it fails

Every error is an `AlgoError`; its `kind` says what went wrong, and `source` gives
the error of the DH layer underneath, where there is one.

| `ErrorKind` | When |
|---|---|
| `UnknownAgreement` | The name is not DH or DIFFIEHELLMAN, or the `dh` feature is off |
| `UnknownGenerator` | Likewise for the generator |
| `InvalidKeyGenParams` | The generator has no group: `generate` without `init`, `key_pair::generate("DH")`, or `init` with a size alone. Or the group is bad, such as an even p |
| `InvalidParams` | `init` with a key that is not DH, or with user keying material. `calculate` with an ephemeral key, a public key that is not DH, of another group or weak, or a secret of 1 |
| `NotInitialized` | `calculate` before a successful `init` |
| `DataLength` | `calculate_agreement` with a buffer shorter than `agreement_size` |

```rust
use tc_algo::agreement;
use tc_algo::generate;
use tc_algo::{AlgoError, ErrorKind};
use tc_dh_key::standard_groups::{rfc3526_2048, rfc7919_ffdhe2048};

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("DH")?;
    generator.init(rfc7919_ffdhe2048())?;
    let mine = generator.generate()?;

    // A public key of another group
    generator.init(rfc3526_2048())?;
    let other = generator.generate()?;

    let error = agreement::calculate("DH", &mine.private.into(), &other.public.into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
    Ok(())
}
```

## Groups

A group is a prime p, a generator g and the order q of the subgroup g generates. It
is public, and both parties must use the same one. `tc_dh_key::standard_groups` has
those the IETF published, after Bouncy Castle's `DHStandardGroups`. Each is a safe
prime p, with g = 2 and q = (p - 1) / 2, and each is a function, as its numbers are
too large to be constants.

| Function | Bits of p | Bits of x | For |
|---|---:|---:|---|
| `rfc7919_ffdhe2048` | 2048 | 225 | New systems; TLS 1.3 names it ffdhe2048 |
| `rfc7919_ffdhe3072` | 3072 | 275 | Likewise |
| `rfc7919_ffdhe4096` | 4096 | 325 | Likewise |
| `rfc7919_ffdhe6144` | 6144 | 375 | Likewise |
| `rfc7919_ffdhe8192` | 8192 | 400 | Likewise |
| `rfc3526_1536` | 1536 | 200 | IKE group 5; too small for new keys |
| `rfc3526_2048` | 2048 | 225 | IKE group 14 |
| `rfc3526_3072` | 3072 | 275 | IKE group 15 |
| `rfc3526_4096` | 4096 | 325 | IKE group 16 |
| `rfc3526_6144` | 6144 | 375 | IKE group 17 |
| `rfc3526_8192` | 8192 | 400 | IKE group 18 |
| `rfc2409_768` | 768 | | Old data only: far too small |
| `rfc2409_1024` | 1024 | | Old data only: too small |

Bits of x is the length of the private key the generator makes, as RFC 7919
recommends; it keeps the agreement fast without weakening it below the strength of
p. `rfc4306_768` and `rfc5996_768` are other names for `rfc2409_768`, and
`rfc4306_1024` and `rfc5996_1024` for `rfc2409_1024`.

For a new system, take `rfc7919_ffdhe2048` or larger. A group of your own, such as
one read from a certificate, is a `tc_dh_key::DhParameters` of p and g, with q when
it is known. `tc_dh_key::DhParametersGenerator` makes a new safe-prime group, which
takes from tens of seconds to minutes at 2048 bits; a standard group is as safe and
costs nothing.

## Names

| Name | Aliases | OID | Feature | Default |
|---|---|---|---|:---:|
| DH | DIFFIEHELLMAN | | `dh` | ✓ |

Names match without regard to ASCII case. DH has no OID, in either factory, as in
Bouncy Castle: the OIDs of DH, such as PKCS #3's dhKeyAgreement, name a key, not an
agreement or a generator.

## Notes

- **The other party's public key is checked** before it is used: it must be of the
  same group as your private key (p, g and q), at least 2 and at most p - 2, and in
  the subgroup of order q when the group has q, as every standard group does. p is
  at most 16384 bits. A secret of 1 is refused too. Without these checks, a forged
  public key could pull the secret into a small subgroup and give away bits of the
  private key.
- **Timing**: making x and calculating `g^x` and `y^x` take time that does not depend
  on x. Only the number of candidates for x drawn and dropped shows, and it says
  nothing about the x kept. The checks of the public key take time that depends on
  the public key and the group, both public.
- **Forward secrecy** comes from making a new key pair for each exchange and dropping
  it afterwards. A key pair kept for months makes every secret it took part in
  readable to whoever later takes the private key.
- **The secret is p bytes long**, leading zeros included. Bouncy Castle returns it as
  an integer, which drops them; pad it back to compare with Bouncy Castle.
- **No key is printed**: the `Debug` output of a key pair, an agreement or a
  `SharedSecret` shows the algorithm or the length, never the key or the secret.
