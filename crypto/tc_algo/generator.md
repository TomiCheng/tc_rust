# Key generators

`tc_algo::generate` creates key generators and key pair generators by name or by
OID, after Bouncy Castle's `GeneratorUtilities`. A key generator makes a `SecretKey`;
a key pair generator makes a `KeyPair`, an `AnyPublicKey` and an `AnyPrivateKey`.

## Enabling generators

Each generator comes with the feature of its algorithm, listed in the
[tables](#algorithms) below. AES and RSA are both in the default features.

```toml
[dependencies]
# Keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["aes"] }
```

## Usage

### In one step

Find the generator by name and make one key with its defaults and the operating
system's randomness.

```rust
use tc_algo::AlgoError;
use tc_algo::generate;

fn main() -> Result<(), AlgoError> {
    let key = generate::generate_key("AES256")?;
    let pair = generate::generate_key_pair("RSA")?;
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
    let mut generator = generate::get_key_generator("AES")?;
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
    let mut generator = generate::get_key_pair_generator("RSA")?;
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

### With randomness of your own

`with_rng` takes any `CryptoRng + Send` in place of the operating system's. A seeded
generator makes the same key every time, which suits tests and nothing else.

```rust
use rand::SeedableRng;
use rand::rngs::StdRng;
use tc_algo::AlgoError;
use tc_algo::generate;

fn main() -> Result<(), AlgoError> {
    let mut generator = generate::get_key_generator("AES256")?;
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
    let aes = generate::get_key_generator("2.16.840.1.101.3.4.1.46")?;
    assert_eq!(aes.entry().name(), "AES256");

    let error = generate::get_key_pair_generator("no-such-key").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownGenerator);
    Ok(())
}
```

`get_key_generator_by_oid` and `get_key_pair_generator_by_oid` take an `Asn1Oid`.

### Looking at the tables

```rust
use tc_algo::generate;

for entry in generate::key_generators() {
    println!("{entry}"); // e.g. `AES128  [id-aes128-ECB, id-aes128-CBC, ...]`
}
for entry in generate::key_pair_generators() {
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
| RSA | 2048 bits, exponent 65537, certainty 100 | 1.2.840.113549.1.1.1 | `Strength`, `Rsa` | `rsa` |

Bits and Defaults are what the generator makes without `init`. Params are the
`KeyGenParams` variants its `init` takes.

The eight OIDs of an AES size are, in order, those of ECB, CBC, OFB, CFB, key wrap,
GCM, CCM and key wrap with padding, as in Bouncy Castle.

### Notes

- **AES without a size** makes 192 bits, as in Bouncy Castle, so name the size or
  give it to `init`. AESWRAP is the same generator.
- **Every AES row takes every AES size**: AES128 initialized with 256 bits makes a
  256-bit key.
- **Certainty** is that of Bouncy Castle: the chance that a prime factor is in fact
  composite is at most 2^-certainty.
- **An IV or nonce** does not come from here. Fill it with random bytes of the size
  the cipher takes, as the cipher examples do.
