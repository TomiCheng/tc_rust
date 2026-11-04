# ECMQV

ECMQV is the Menezes-Qu-Vanstone agreement on an elliptic curve, of SEC 1 and IEEE
P1363. Each party has two key pairs on the same curve: a **static** one, kept for long,
whose public key the other party already knows and trusts, such as from a certificate;
and an **ephemeral** one, made for this exchange. They swap ephemeral public keys, and
each combines its own two private keys with the other's two public keys. Both reach
the same point, and its x coordinate is their shared secret.

The secret depends on both static keys, so only the holders of the static private keys
can reach it: the agreement authenticates both parties without a signature. The
ephemeral keys make the secret of each exchange a new one.

In `tc_algo` this takes two factories: `generate::key_pair` makes the key pairs and
`agreement` calculates the secret, after Bouncy Castle's `GeneratorUtilities` and
`AgreementUtilities`. The generator is `"EC"`, the agreement `"ECMQV"`.

## Enabling ECMQV

ECMQV comes with the `ecmqv` feature. It enables `ec`, the EC keys and their generator on the
prime curves. `ec-f2m` adds the binary curves and `ec-small-curves` the weak ones.

```toml
[dependencies]
tc_algo = { version = "0.1", features = ["ecmqv"] }
```

## Usage

### Both parties, step by step

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, AgreementPeer, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp256r1)?;

    // 1. Each party has a static key pair, whose public key the other already knows ...
    let alice_static = generator.generate()?;
    let bob_static = generator.generate()?;

    // 2. ... and makes an ephemeral key pair, whose public key it sends to the other
    let alice_ephemeral = generator.generate()?;
    let bob_ephemeral = generator.generate()?;

    // 3. Alice combines her two private keys with Bob's two public keys ...
    let params =
        AnyAgreementParams::new(alice_static.private).with_ephemeral(alice_ephemeral.private);
    let peer = AgreementPeer::new(bob_static.public).with_ephemeral(bob_ephemeral.public);
    let mut agreement = agreement::get_by_name("ECMQV")?;
    agreement.init(&params)?;
    let alice_secret = agreement.calculate(&peer)?;

    // ... and Bob combines his with Alice's, for the same secret
    let params =
        AnyAgreementParams::new(bob_static.private).with_ephemeral(bob_ephemeral.private);
    let peer = AgreementPeer::new(alice_static.public).with_ephemeral(alice_ephemeral.public);
    let mut agreement = agreement::get_by_name("ECMQV")?;
    agreement.init(&params)?;
    let bob_secret = agreement.calculate(&peer)?;

    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
```

`init` takes this party's keys in an `AnyAgreementParams`: the static private key,
and the ephemeral private key by `with_ephemeral`. `calculate` takes the other party's
keys in an `AgreementPeer`: the static public key, and the ephemeral public key by
`with_ephemeral`. Both ephemeral keys are required, so `.into()`, which makes either
from one key alone, is not enough here.

All four keys must be on the same curve, the one of the static keys. Make a new
ephemeral key pair for each exchange; the static one stays.

### In one step

`agreement::calculate` finds the agreement, initializes it and calculates.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, AgreementPeer, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp384r1)?;
    let (mine, my_ephemeral) = (generator.generate()?, generator.generate()?);
    let (theirs, their_ephemeral) = (generator.generate()?, generator.generate()?);

    let params = AnyAgreementParams::new(mine.private).with_ephemeral(my_ephemeral.private);
    let peer = AgreementPeer::new(theirs.public).with_ephemeral(their_ephemeral.public);
    let secret = agreement::calculate("ECMQV", &params, &peer)?;
    Ok(())
}
```

### The secret is not yet a key

The secret is the x coordinate of the shared point, as many bytes as a coordinate of
the curve has, with leading zeros: 32 for P-256. Its bytes are not uniformly random,
so do not use them as a key: derive the key from them with a KDF, such as HKDF or the
KDF of X9.63, and give the KDF what both parties agree to bind the key to.

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
use tc_algo::agreement::{self, Agreement, AgreementPeer, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp256r1)?;
    let (mine, my_ephemeral) = (generator.generate()?, generator.generate()?);
    let (theirs, their_ephemeral) = (generator.generate()?, generator.generate()?);

    let mut agreement = agreement::get_by_name("ECMQV")?;
    agreement.init(&AnyAgreementParams::new(mine.private).with_ephemeral(my_ephemeral.private))?;
    let peer = AgreementPeer::new(theirs.public).with_ephemeral(their_ephemeral.public);
    let mut secret = vec![0; agreement.agreement_size()]; // 32 bytes
    agreement.calculate_agreement(&peer, &mut secret)?;
    Ok(())
}
```

`agreement_size` panics before a successful `init`; `calculate` returns
`NotInitialized` instead.

### When it fails

Every error is an `AlgoError`; its `kind` says what went wrong, and `source` gives
the error of the ECMQV layer underneath, where there is one.

| `ErrorKind` | When |
|---|---|
| `UnknownAgreement` | The name is not ECMQV, or the `ecmqv` feature is off |
| `UnknownGenerator` | The name is not EC, ECDH, ECIES, ECDHC or ECMQV, or the `ec` feature is off |
| `InvalidKeyGenParams` | The generator has no curve: `generate` without `init`, `key_pair::generate("EC")`, or `init` with a size that names none of the curves |
| `InvalidParams` | `init` with a key that is not EC, without an ephemeral key, with the two keys on two curves, or with user keying material. `calculate` without the other party's ephemeral key, with a public key that is not EC or is on another curve, or with keys that give a shared point at infinity |
| `NotInitialized` | `calculate` before a successful `init` |
| `DataLength` | `calculate_agreement` with a buffer shorter than `agreement_size` |

```rust
use tc_algo::agreement;
use tc_algo::generate;
use tc_algo::params::EcCurve;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp256r1)?;
    let mine = generator.generate()?;

    // The static key alone, without an ephemeral key
    let mut agreement = agreement::get_by_name("ECMQV")?;
    let error = agreement.init(&mine.private.into()).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
    Ok(())
}
```

## Curves

ECMQV takes the curves ECDH takes, named by an `EcCurve`; they are listed with the
feature of each in [ecdh.md](ecdh.md#curves). For a new system, take P-256 or larger.

## Names

| Factory | Name | Aliases | OID | Feature |
|---|---|---|---|---|
| `agreement` | ECMQV | | | `ecmqv` |
| `generate::key_pair` | EC | ECDH, ECIES, ECDHC, ECMQV | 15 of the ECDH and ECMQV schemes with a KDF | `ec` |

Names match without regard to ASCII case, and a dotted OID works wherever a name does.
The agreement has no OID, as in Bouncy Castle: the OIDs of MQV, such as
mqvSinglePass-sha256kdf-scheme (1.3.132.1.15.1), name ECMQV followed by a KDF.
Bouncy Castle finds its ECMQV generator by those OIDs, and so does the EC generator
here, which serves all the EC names.

## Notes

- **This party's ephemeral public key** is computed from its private key, so only the
  private key goes into the params. Bouncy Castle's `MqvPrivateParameters` take it as
  well, to save that multiplication.
- **The other party's public keys are checked** before they are used: each must be a
  point of the private keys' curve and not the point at infinity, and the shared
  point must not be at infinity either.
- **The cofactor** is part of ECMQV in SEC 1, so on the binary curves, whose cofactor
  is 2 or 4, there is no other version to choose, as there is for ECDH.
- **Timing**: the private keys go only into modular arithmetic and multiplications
  whose time does not depend on them. What depends on the ephemeral public keys, as
  the reduction of their x coordinates does, depends on public values only.
- **The secret is as long as a coordinate**, leading zeros included. Bouncy Castle
  returns it as an integer, which drops them; pad it back to compare with Bouncy
  Castle.
- **No key is printed**: the `Debug` output of an EC private key, an agreement or a
  `SharedSecret` shows the curve or the length, never the key or the secret.
