# GOST VKO

VKO is the key agreement of the Russian GOST R 34.10 standards, in RFC 4357 and
RFC 7836. Each party makes a key pair on the same GOST curve, they swap public keys and
agree on a UKM, a random value both know, and each multiplies the other's public key by
its own private key and by the UKM. Both reach the same point, and the GOST R 34.11
hash of its coordinates is their shared secret; someone who saw only the public keys
and the UKM does not.

There are three agreements, one per hash:

- **ECGOST3410-2012-256**: GOST R 34.11-2012, 256 bits; a 32-byte secret.
- **ECGOST3410-2012-512**: GOST R 34.11-2012, 512 bits; a 64-byte secret.
- **ECGOST3410**: GOST R 34.11-94, the hash of GOST R 34.10-2001; a 32-byte secret.

In `tc_algo` this takes two factories: `generate::key_pair` makes the key pairs and
`agreement` calculates the secret, after Bouncy Castle's `GeneratorUtilities` and
`AgreementUtilities`. The keys are EC keys, from the `"EC"` generator on a GOST curve.

## Enabling VKO

The 2012 agreements come with the `ecvko` feature, which is in the default features.
It enables `ec-gost`, the GOST curves, and both GOST R 34.11-2012 hashes. ECGOST3410
needs the `gost3411` feature as well, which is not in the default, as GOST R 34.11-94
is kept for old data only.

```toml
[dependencies]
tc_algo = "0.1"

# Or with ECGOST3410 of 2001 too
tc_algo = { version = "0.1", features = ["gost3411"] }
```

## Usage

### Both parties, step by step

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    // 1. Both parties take the same GOST curve
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::GostTc26ParamSet256A)?;

    // 2. Each makes a key pair and sends the public key to the other
    let alice = generator.generate()?;
    let bob = generator.generate()?;

    // 3. One of them picks the UKM, random bytes, and sends it along
    let ukm = vec![0x1d, 0x80, 0x60, 0x3c, 0x85, 0x44, 0xc7, 0x27];

    // 4. Alice combines her private key and the UKM with Bob's public key ...
    let mut agreement = agreement::get_by_name("ECGOST3410-2012-256")?;
    agreement.init(&AnyAgreementParams::new(alice.private).with_ukm(ukm.clone()))?;
    let alice_secret = agreement.calculate(&bob.public.into())?;

    // ... and Bob his with Alice's, for the same secret
    let mut agreement = agreement::get_by_name("ECGOST3410-2012-256")?;
    agreement.init(&AnyAgreementParams::new(bob.private).with_ukm(ukm))?;
    let bob_secret = agreement.calculate(&alice.public.into())?;

    assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    Ok(())
}
```

`init` takes this party's private key and the UKM in an `AnyAgreementParams`, the key
by `new` and the UKM by `with_ukm`; the UKM is required, so `.into()`, which makes the
params from the key alone, is not enough here. `calculate` takes the other party's
public key in an `AgreementPeer`, which `.into()` makes from the key.

The hash need not match the curve: example 7 of RFC 7836 takes the 256-bit hash on a
512-bit curve. Use the pair the protocol names.

### In one step

`agreement::calculate` finds the agreement, initializes it and calculates.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::GostTc26ParamSet512A)?;
    let (alice, bob) = (generator.generate()?, generator.generate()?);
    let ukm = vec![1, 2, 3, 4, 5, 6, 7, 8];

    let params = AnyAgreementParams::new(alice.private).with_ukm(ukm);
    let secret = agreement::calculate("ECGOST3410-2012-512", &params, &bob.public.into())?;
    Ok(())
}
```

### The secret

The secret is the hash of the shared point, already of uniform bytes. RFC 4357 and
RFC 7836 take it as a key-encryption key, as for the GOST 28147-89 key wrap, or put it
through their KDF first; follow the protocol. It is still a `SharedSecret` here, not a
`SecretKey`: `as_bytes` gives its bytes to the next step, and they are wiped when it is
dropped. It cannot be cloned, which keeps one copy of it, nor compared with `==`, which
would take time that depends on its bytes.

### Into a buffer of your own

`AnyAgreement` also implements the `Agreement` and `AgreementInit` traits, which
`tc_algo::agreement` re-exports, so it fits generic code. `calculate_agreement`
writes the secret into the first `agreement_size` bytes of a buffer: the length of the
hash.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::{self, Agreement, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::GostTc26ParamSet256A)?;
    let (alice, bob) = (generator.generate()?, generator.generate()?);

    let mut agreement = agreement::get_by_name("ECGOST3410-2012-256")?;
    agreement.init(&AnyAgreementParams::new(alice.private).with_ukm(vec![7; 8]))?;
    let mut secret = [0; 32];
    agreement.calculate_agreement(&bob.public.into(), &mut secret)?;
    Ok(())
}
```

`agreement_size` panics before a successful `init`; `calculate` returns
`NotInitialized` instead.

### When it fails

Every error is an `AlgoError`; its `kind` says what went wrong, and `source` gives
the error of the VKO layer underneath, where there is one.

| `ErrorKind` | When |
|---|---|
| `UnknownAgreement` | The name or OID is not one of the table below, or its features are off |
| `InvalidParams` | `init` with a key that is not EC, without a UKM, or with an ephemeral key. `calculate` with an ephemeral key, a public key that is not EC or is on another curve, or keys and a UKM that give a shared point at infinity, as a UKM of zero does |
| `NotInitialized` | `calculate` before a successful `init` |
| `DataLength` | `calculate_agreement` with a buffer shorter than `agreement_size` |

```rust
use tc_algo::agreement::{self, AnyAgreementParams};
use tc_algo::generate;
use tc_algo::params::EcCurve;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::GostTc26ParamSet256A)?;
    let mine = generator.generate()?;

    // The private key alone, without a UKM
    let mut agreement = agreement::get_by_name("ECGOST3410-2012-256")?;
    let error = agreement
        .init(&AnyAgreementParams::new(mine.private))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidParams);
    Ok(())
}
```

## Curves

VKO takes the GOST curves, named by an `EcCurve`, which the `ec-gost` feature enables:
`GostCryptoProA`, `GostCryptoProB` and `GostCryptoProC` of 2001, and
`GostTc26ParamSet256A`, `GostTc26ParamSet512A`, `GostTc26ParamSet512B` and
`GostTc26ParamSet512C` of 2012. [ecdh.md](ecdh.md#curves) lists them with their other
names. As in Bouncy Castle, the agreements take the other EC curves too, but the GOST
protocols name GOST curves.

## Names

| Name | Aliases | OIDs | Secret | Feature | Default |
|---|---|---|---:|---|:---:|
| ECGOST3410-2012-256 | | 1.2.643.7.1.1.6.1 (id-tc26-agreement-gost-3410-12-256), 1.2.643.7.1.1.1.1 (id-tc26-gost3410-12-256) | 32 bytes | `ecvko` | ✓ |
| ECGOST3410-2012-512 | | 1.2.643.7.1.1.6.2 (id-tc26-agreement-gost-3410-12-512), 1.2.643.7.1.1.1.2 (id-tc26-gost3410-12-512) | 64 bytes | `ecvko` | ✓ |
| ECGOST3410 | GOST-3410-2001 | 1.2.643.2.2.19 (id-GostR3410-2001), 1.2.643.2.2.96 (id-GostR3410-2001-CryptoPro-ESDH) | 32 bytes | `ecvko` and `gost3411` | |

Names match without regard to ASCII case, and a dotted OID works wherever a name does.
As in Bouncy Castle, each agreement goes by the OID of its agreement and by that of its
key.

## Notes

- **The UKM** is read as a little-endian integer, as RFC 7836 and Bouncy Castle read
  it. A UKM of zero gives the point at infinity, which `calculate` refuses.
- **The other party's public key is checked** before it is used: it must be a point of
  the private key's curve and not the point at infinity.
- **The cofactor** is part of VKO: the private key is multiplied by the cofactor and
  the UKM, so on the GOST curves whose cofactor is 4 the small subgroup plays no part.
- **Timing**: the scalar multiplication takes time that does not depend on the private
  key. Reading the UKM and the checks of the public key take time that depends on the
  UKM, the public key and the curve, all public.
- **Forward secrecy** comes from making a new key pair for each exchange and dropping
  it afterwards; a new UKM alone does not give it.
- **No key is printed**: the `Debug` output of an EC private key, an agreement or a
  `SharedSecret` shows the curve or the length, never the key or the secret.
