# Key generators

`tc_algo::generate` creates key generators and key pair generators by name or by
OID, after Bouncy Castle's `GeneratorUtilities`, in two factories that work alike
and like the other factories of `tc_algo`, with `get_by_name`, `get_by_oid`,
`algorithms` and a one-step `generate`:

- `generate::key` makes a `SecretKey`, for the algorithms that take one, such as AES.
- `generate::key_pair` makes a `KeyPair`, an `AnyPublicKey` and an `AnyPrivateKey`,
  such as for RSA, EC, DH, X25519 or X448.

## Enabling generators

Nothing is on by default. Each generator comes with the feature of its algorithm, listed in
the [tables](#algorithms) below.

```toml
[dependencies]
tc_algo = { version = "0.1", features = ["aes"] }
```

## Usage

### In one step

Find the generator by name and make one key with its defaults and the operating
system's randomness.

```rust
use tc_algo::AlgoError;
use tc_algo::generate;

fn main() -> Result<(), AlgoError> {
    let key = generate::key::generate("AES256")?;
    let pair = generate::key_pair::generate("RSA")?;
    Ok(())
}
```

### In three steps

Get a generator, initialize it, then generate. `init` is optional: without it the
generator uses the defaults of its row. Each key goes into the params of the factory
that uses it.

```rust
use tc_algo::AlgoError;
use tc_algo::generate::{self, KeyGenParams};
use tc_algo::params::{AnyKeyParams, AnyParams};

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key::get_by_name("AES")?;
    generator.init(KeyGenParams::Strength { bits: 256 })?;
    let key = generator.generate()?;

    let params = AnyParams::new(AnyKeyParams::Secret(key));
    Ok(())
}
```

### With RSA parameters

`KeyGenParams::rsa()` starts at Bouncy Castle's defaults, and each `with_` method
changes one of them. `KeyGenParams::Strength` sets the size alone and keeps the
other two.

```rust
use tc_algo::AlgoError;
use tc_algo::generate::{self, KeyGenParams};
use tc_algo::params::{AnyKeyParams, AnyParams};

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("RSA")?;
    generator.init(KeyGenParams::rsa().with_bits(3072))?;
    let pair = generator.generate()?;

    // The public key to encrypt or verify, the private key to decrypt or sign
    let public = AnyParams::new(AnyKeyParams::Public(pair.public));
    let private = AnyParams::new(AnyKeyParams::Private(pair.private));
    Ok(())
}
```

`init` refuses params of a kind the generator does not take, such as RSA params for
AES or an AES size other than 128, 192 or 256, with `InvalidKeyGenParams`, and keeps
the ones it had. The values RSA checks itself, such as a size too small or an even
exponent, fail in `generate` instead, with the same kind and the RSA error as the
source.

### With a DH group

A DH generator has no default: `init` takes the group both parties share, a
`DhParameters` of `tc_dh_key`, the crate whose keys `AnyPrivateKey::Dh` holds, such
as one of its `standard_groups`. A size alone names no group, so `Strength` is
refused, as in Bouncy Castle, and `key_pair::generate("DH")` fails for want of a group.

```rust
use tc_algo::AlgoError;
use tc_algo::agreement::AnyAgreementParams;
use tc_algo::generate;
use tc_dh_key::standard_groups::rfc7919_ffdhe2048;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("DH")?;
    generator.init(rfc7919_ffdhe2048())?;
    let pair = generator.generate()?;

    // The private key for this party's agreement, the public key for the other party
    let params = AnyAgreementParams::new(pair.private);
    let public = pair.public;
    Ok(())
}
```

The group is checked in `generate`, as RSA's values are: a bad one fails with
`InvalidKeyGenParams` and the DH error as the source.

### With an EC curve

An EC generator has no default curve either: `init` takes an `EcCurve`, or a size
alone, which takes the curve Bouncy Castle takes for it: P-224, P-256, P-384 or P-521
for 224, 256, 384 or 521 bits.

```rust
use tc_algo::AlgoError;
use tc_algo::generate::{self, KeyGenParams};
use tc_algo::params::EcCurve;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key_pair::get_by_name("EC")?;
    generator.init(EcCurve::Secp256r1)?;
    let pair = generator.generate()?;

    // The same curve by its size
    generator.init(KeyGenParams::Strength { bits: 256 })?;
    let pair = generator.generate()?;
    Ok(())
}
```

`init` refuses a size that names none of the curves with `InvalidKeyGenParams`, such
as 239 bits, which names Bouncy Castle's prime239v1. The curves each feature enables
are listed in [ecdh.md](agreement/ecdh.md#curves).

### With randomness of your own

`with_rng` takes any `CryptoRng + Send` in place of the operating system's. A seeded
generator makes the same key every time, which suits tests and nothing else.

```rust
use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::AlgoError;
use tc_algo::generate;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::key::get_by_name("AES256")?;
    let key = generator.with_rng(StdRng::seed_from_u64(7)).generate()?;
    Ok(())
}
```

### By name or OID

Names match without regard to ASCII case, aliases are accepted, and a dotted OID
string works wherever a name does. The generator reports its canonical name.

```rust
use tc_algo::generate;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let aes = generate::key::get_by_name("2.16.840.1.101.3.4.1.46")?;
    assert_eq!(aes.entry().name(), "AES256");

    let error = generate::key_pair::get_by_name("no-such-key").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
    Ok(())
}
```

`key::get_by_oid` and `key_pair::get_by_oid` take an `Asn1Oid`.

### Looking at the tables

```rust
use tc_algo::generate;

for entry in generate::key::algorithms() {
    println!("{entry}"); // e.g. `AES128  [id-aes128-ECB, id-aes128-CBC, ...]`
}
for entry in generate::key_pair::algorithms() {
    println!("{entry}"); // e.g. `RSA  [rsaEncryption]`
}
```

`KeyGenerator` and `KeyPairGenerator` are `Send`. Their `Debug` output shows the
name and the params, never the randomness. `SecretKey` shows only its length and
wipes its bytes on drop; `AnyPrivateKey` shows only its algorithm.

## Algorithms

### Key generators

| Name | Aliases | Bits | OID | Params | Feature |
|---|---|---:|---|---|---|
| AES | AESWRAP | 192 | | `Strength` | `aes` |
| AES128 | | 128 | 2.16.840.1.101.3.4.1.1 to .8 | `Strength` | `aes` |
| AES192 | | 192 | 2.16.840.1.101.3.4.1.21 to .28 | `Strength` | `aes` |
| AES256 | | 256 | 2.16.840.1.101.3.4.1.41 to .48 | `Strength` | `aes` |

### Key pair generators

| Name | Defaults | OID | Params | Feature |
|---|---|---|---|---|
| DH | none: `init` is required | | `Dh` | `dh` |
| EC | none: `init` is required | 1.3.133.16.840.63.0.2, .3 and .16, 1.3.132.1.11.0 to .3, 1.3.132.1.14.0 to .3, 1.3.132.1.15.0 to .3 | `Strength`, `Ec` | `ec` |
| RSA | 2048 bits, exponent 65537, certainty 100 | 1.2.840.113549.1.1.1 | `Strength`, `Rsa` | `rsa` |
| X25519 | 255 bits | 1.3.101.110 | `Strength` of 255 | `x25519` |
| X448 | 448 bits | 1.3.101.111 | `Strength` of 448 | `x448` |

Bits and Defaults are what the generator makes without `init`. Params are the
`KeyGenParams` variants its `init` takes.

The eight OIDs of an AES size are, in order, those of ECB, CBC, OFB, CFB, key wrap,
GCM, CCM and key wrap with padding, as in Bouncy Castle.

### Notes

- **AES without a size** makes 192 bits, as in Bouncy Castle, so name the size or
  give it to `init`. AESWRAP is the same generator.
- **Every AES row takes every AES size**: AES128 initialized with 256 bits makes a
  256-bit key.
- **DH** has DIFFIEHELLMAN as its alias and, as in Bouncy Castle, no OID: the OIDs
  of DH keys name the key in a certificate, not a generator.
- **EC** has ECDH, ECIES, ECDHC and ECMQV as its aliases. Bouncy Castle has a
  generator for each of EC, ECDH, ECDHC and ECMQV, whose keys differ only in the
  algorithm name they carry; the keys here carry none, so one generator serves. Its
  OIDs are those of Bouncy Castle's EC and ECMQV generators: the ECDH and ECMQV
  schemes with a KDF of X9.63 and SEC 1.
- **X25519 and X448** have one size each, so `init` is never needed: it takes
  `Strength` of 255 or 448 bits, Bouncy Castle's strength for each, and refuses any
  other. Their OIDs are id-X25519 and id-X448 of RFC 8410, as in Bouncy Castle.
- **Certainty** is that of Bouncy Castle: the chance that a prime factor is in fact
  composite is at most 2^-certainty.
- **An IV or nonce** does not come from here. Fill it with random bytes of the size
  the cipher takes, as the cipher examples do.
