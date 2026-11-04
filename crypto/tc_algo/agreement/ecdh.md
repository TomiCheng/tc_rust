# ECDH

ECDH is Diffie-Hellman on an elliptic curve, as IEEE P1363 and SEC 1 define it: each
party makes a key pair on the same curve, they swap public keys, and each multiplies
the other's public key by its own private key. Both reach the same point, and its x
coordinate is their shared secret; someone who saw only the public keys does not.

There are two agreements. **ECDH** takes the point as it is; **ECDHC** multiplies by
the cofactor of the curve as well. On a curve whose cofactor is 1, as most prime curves
have, the two give the same secret; on the binary curves and two of the GOST curves
they do not, so both parties must use the same one.

In `tc_algo` this takes two factories: `generate::key_pair` makes the key pairs and
`agreement` calculates the secret, after Bouncy Castle's `GeneratorUtilities` and
`AgreementUtilities`. The generator is `"EC"`, the agreements `"ECDH"` and `"ECDHC"`.

## Enabling ECDH

ECDH and ECDHC come with the `ecdh` feature. It enables `ec`, the EC keys and their generator
on the prime curves. `ec-gost` adds the GOST curves, `ec-f2m` the binary curves and
`ec-small-curves` the weak ones.

```toml
[dependencies]
tc_algo = { version = "0.1", features = ["ecdh"] }

# Or with the binary curves too
tc_algo = { version = "0.1", features = ["ec-f2m"] }
```

## Usage

### Both parties, step by step

```rust
use tc_algo::AlgoError;
use tc_algo::agreement;
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    // 1. Both parties take the same curve, here P-256
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp256r1)?;

    // 2. Each makes a key pair and sends the public key to the other
    let alice = generator.generate()?;
    let bob = generator.generate()?;

    // 3. Alice combines her private key with Bob's public key ...
    let mut agreement = agreement::get_by_name("ECDH")?;
    agreement.init(&alice.private.into())?;
    let alice_secret = agreement.calculate(&bob.public.into())?;

    // ... and Bob combines his with Alice's, for the same secret
    let mut agreement = agreement::get_by_name("ECDH")?;
    agreement.init(&bob.private.into())?;
    let bob_secret = agreement.calculate(&alice.public.into())?;

    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
```

`init` takes this party's private key in an `AnyAgreementParams`, and `calculate`
takes the other party's public key in an `AgreementPeer`. `.into()` makes either from
the key alone: the params from an `AnyPrivateKey`, the peer from an `AnyPublicKey`.
One agreement calculates as many secrets as you like with the key it was initialized
with.

The generator has no default curve: `init` takes an `EcCurve`, or a size alone,
which takes the curve Bouncy Castle takes for it: 224, 256, 384 or 521 bits for
P-224, P-256, P-384 or P-521.

### In one step

`agreement::calculate` finds the agreement, initializes it and calculates.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement;
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp384r1)?;
    let (alice, bob) = (generator.generate()?, generator.generate()?);

    let secret = agreement::calculate("ECDH", &alice.private.into(), &bob.public.into())?;
    Ok(())
}
```

### On the other party's curve

When the other party chose the curve, its public key tells which: `curve()` of an
`AnyEcPublicKey`. Make your key pair on it, then answer with your public key.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, SharedSecret};
use tc_algo::generate;
use tc_algo::params::AnyPublicKey;

// Your public key to send back, and the secret
fn answer(theirs: AnyPublicKey) -> Result<(AnyPublicKey, SharedSecret), AlgoError> {
    let AnyPublicKey::Ec(key) = &theirs else {
        panic!("not an EC key");
    };
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(key.curve())?;
    let mine = generator.generate()?;

    let secret = agreement::calculate("ECDH", &mine.private.into(), &theirs.into())?;
    Ok((mine.public, secret))
}
```

### ECDH or ECDHC

ECDHC is `"ECDHC"`, or `"ECCDH"` as Bouncy Castle also calls it, and takes the same
keys and the same steps. On a curve whose cofactor is 1 it gives what ECDH gives. On
a curve whose cofactor is 2 or 4, as the [table](#curves) shows for the binary curves
and two GOST curves, its secret is another, so take the one the protocol names. Either way, a public key with a part
outside the curve's main subgroup cannot pull bits of the private key out: ECDH clears
that part too, as Bouncy Castle does, at no change to its secret.

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
use tc_algo::agreement::{self, Agreement};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp256r1)?;
    let (alice, bob) = (generator.generate()?, generator.generate()?);

    let mut agreement = agreement::get_by_name("ECDH")?;
    agreement.init(&alice.private.into())?;
    let mut secret = vec![0; agreement.agreement_size()]; // 32 bytes
    agreement.calculate_agreement(&bob.public.into(), &mut secret)?;
    Ok(())
}
```

`agreement_size` panics before a successful `init`; `calculate` returns
`NotInitialized` instead.

### When it fails

Every error is an `AlgoError`; its `kind` says what went wrong, and `source` gives
the error of the ECDH layer underneath, where there is one.

| `ErrorKind` | When |
|---|---|
| `UnknownAgreement` | The name is not ECDH, ECDHC or ECCDH, or the `ecdh` feature is off |
| `UnknownGenerator` | The name is not EC, ECDH, ECIES, ECDHC or ECMQV, or the `ec` feature is off |
| `InvalidKeyGenParams` | The generator has no curve: `generate` without `init`, `key_pair::generate("EC")`, or `init` with a size that names none of the curves |
| `InvalidParams` | `init` with a key that is not EC, with an ephemeral key, or with user keying material. `calculate` with an ephemeral key, a public key that is not EC or is on another curve, or one that gives a shared point at infinity |
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

    // A public key on another curve
    generator.init(EcCurve::Secp384r1)?;
    let other = generator.generate()?;

    let error = agreement::calculate("ECDH", &mine.private.into(), &other.public.into())
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
    Ok(())
}
```

## Curves

A curve is named by an `EcCurve`. It is public, and both parties must use the same
one.

| `EcCurve` | Also known as | Bytes of the secret | Cofactor | Feature |
|---|---|---:|---:|---|
| `Secp224k1` | | 28 | 1 | `ec` |
| `Secp224r1` | P-224 | 28 | 1 | `ec` |
| `Secp256k1` | | 32 | 1 | `ec` |
| `Secp256r1` | P-256, prime256v1 | 32 | 1 | `ec` |
| `Secp384r1` | P-384 | 48 | 1 | `ec` |
| `Secp521r1` | P-521 | 66 | 1 | `ec` |
| `Sm2p256v1` | the SM2 curve | 32 | 1 | `ec` |
| `GostCryptoProA` | GostR3410-2001-CryptoPro-A, CryptoPro-XchA, TC26 256 paramSetB | 32 | 1 | `ec-gost` |
| `GostCryptoProB` | GostR3410-2001-CryptoPro-B, TC26 256 paramSetC | 32 | 1 | `ec-gost` |
| `GostCryptoProC` | GostR3410-2001-CryptoPro-C, CryptoPro-XchB, TC26 256 paramSetD | 32 | 1 | `ec-gost` |
| `GostTc26ParamSet256A` | TC26 256 paramSetA | 32 | 4 | `ec-gost` |
| `GostTc26ParamSet512A` | TC26 512 paramSetA | 64 | 1 | `ec-gost` |
| `GostTc26ParamSet512B` | TC26 512 paramSetB | 64 | 1 | `ec-gost` |
| `GostTc26ParamSet512C` | TC26 512 paramSetC | 64 | 4 | `ec-gost` |
| `Sect233k1` | K-233 | 30 | 4 | `ec-f2m` |
| `Sect233r1` | B-233 | 30 | 2 | `ec-f2m` |
| `Sect239k1` | | 30 | 4 | `ec-f2m` |
| `Sect283k1` | K-283 | 36 | 4 | `ec-f2m` |
| `Sect283r1` | B-283 | 36 | 2 | `ec-f2m` |
| `Sect409k1` | K-409 | 52 | 4 | `ec-f2m` |
| `Sect409r1` | B-409 | 52 | 2 | `ec-f2m` |
| `Sect571k1` | K-571 | 72 | 4 | `ec-f2m` |
| `Sect571r1` | B-571 | 72 | 2 | `ec-f2m` |

For a new system, take P-256 or larger. The GOST curves are those of GOST R 34.10, of
RFC 4357 and RFC 7836, for the Russian standards; the twelve names Bouncy Castle has
for them come to these seven. `ec-small-curves` adds `Secp112r1` to
`Secp192r1` and, with `ec-f2m`, `Sect113r1` to `Sect193r2`: all are below 112 bits of
security, so keep them for old data. NIST SP 800-186 keeps the binary curves for old
data too.

## Names

| Factory | Name | Aliases | OID | Feature |
|---|---|---|---|---|
| `agreement` | ECDH | | | `ecdh` |
| `agreement` | ECDHC | ECCDH | | `ecdh` |
| `generate::key_pair` | EC | ECDH, ECIES, ECDHC, ECMQV | 15 of the ECDH and ECMQV schemes with a KDF | `ec` |

Names match without regard to ASCII case, and a dotted OID works wherever a name does.
The agreements have no OID, as in Bouncy Castle: the OIDs of ECDH, such as
dhSinglePass-stdDH-sha256kdf-scheme (1.3.132.1.11.1), name ECDH followed by a KDF.
Bouncy Castle finds its EC generator by those OIDs, and so does this one. Bouncy
Castle also has a generator for each of the names EC, ECDH, ECDHC and ECMQV; their
keys differ there only in the algorithm name they carry, which the keys here do not,
so one generator serves under all of them.

## Notes

- **The other party's public key is checked** before it is used: it must be a point
  of the private key's curve and not the point at infinity, and the shared point must
  not be at infinity either.
- **Timing**: making d and calculating `d·G` and `d·Q` take time that does not depend
  on d. Only the number of candidates for d drawn and dropped shows, and it says
  nothing about the d kept. The checks of the public key take time that depends on
  the public key and the curve, both public.
- **Forward secrecy** comes from making a new key pair for each exchange and dropping
  it afterwards. A key pair kept for months makes every secret it took part in
  readable to whoever later takes the private key.
- **The secret is as long as a coordinate**, leading zeros included. Bouncy Castle
  returns it as an integer, which drops them; pad it back to compare with Bouncy
  Castle.
- **No key is printed**: the `Debug` output of an EC private key, an agreement or a
  `SharedSecret` shows the curve or the length, never the key or the secret.
