# SLH-DSA

SLH-DSA, FIPS 205, is a stateless signature built on hashes alone, made to resist a quantum computer.
Its strength rests on the hash, SHA-2 or SHAKE; the `s` sets give small signatures that are slow to
make, and the `f` sets fast ones that are larger.

The `slh-dsa` feature of `tc_algo` has the rows.

## Key pairs

A parameter set and a new pair:

```rust
use tc_algo::params::key::slh_dsa::SlhDsaParameters;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("SLH-DSA", &SlhDsaParameters::SHA2_128F)?;

    let (_public, _private) = pair.into_parts();
    Ok(())
}
```

### Algorithms

| Name | Feature | Params | Public key | Private key |
|---|---|---|---|---|
| `SLH-DSA` | `slh-dsa` | `SlhDsaParameters` | `SlhDsaPublicKey` | `SlhDsaPrivateKey` |

The name is that of Bouncy Castle's `GeneratorUtilities`, and its case does not matter.

### Params

One of the twelve sets of `SlhDsaParameters`, from `SHA2_128S` to `SHAKE_256F`. There is no
default, so `generate_by_name` gives `NotInitialized`, and any other type is `InvalidParams`.

## Signing

From a new pair to a verified signature:

```rust
use tc_algo::params::key::slh_dsa::SlhDsaParameters;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SLH-DSA-SHA2-128F";
    let message = b"attack at dawn";

    // Generate a pair
    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("SLH-DSA", &SlhDsaParameters::SHA2_128F)?;

    // Sign with the private key
    let mut signer = algo.signer().get_by_name(name)?;
    signer.init(pair.private())?;
    signer.update(message)?;
    let signature = signer.sign()?;

    // Verify with the public key
    let mut verifier = algo.signer().get_by_name(name)?;
    verifier.init(pair.public())?;
    verifier.update(message)?;
    assert!(verifier.verify_signature(&signature)?);

    Ok(())
}
```

### Algorithms

| Name | OID | Feature |
|---|---|---|
| `SLH-DSA-SHA2-128S` | `2.16.840.1.101.3.4.3.20` | `slh-dsa` |
| `SLH-DSA-SHA2-128F` | `2.16.840.1.101.3.4.3.21` | `slh-dsa` |
| `SLH-DSA-SHA2-192S` | `2.16.840.1.101.3.4.3.22` | `slh-dsa` |
| `SLH-DSA-SHA2-192F` | `2.16.840.1.101.3.4.3.23` | `slh-dsa` |
| `SLH-DSA-SHA2-256S` | `2.16.840.1.101.3.4.3.24` | `slh-dsa` |
| `SLH-DSA-SHA2-256F` | `2.16.840.1.101.3.4.3.25` | `slh-dsa` |
| `SLH-DSA-SHAKE-128S` | `2.16.840.1.101.3.4.3.26` | `slh-dsa` |
| `SLH-DSA-SHAKE-128F` | `2.16.840.1.101.3.4.3.27` | `slh-dsa` |
| `SLH-DSA-SHAKE-192S` | `2.16.840.1.101.3.4.3.28` | `slh-dsa` |
| `SLH-DSA-SHAKE-192F` | `2.16.840.1.101.3.4.3.29` | `slh-dsa` |
| `SLH-DSA-SHAKE-256S` | `2.16.840.1.101.3.4.3.30` | `slh-dsa` |
| `SLH-DSA-SHAKE-256F` | `2.16.840.1.101.3.4.3.31` | `slh-dsa` |
| `SLH-DSA-SHA2-128S-WITH-SHA256` | `2.16.840.1.101.3.4.3.35` | `slh-dsa` |
| `SLH-DSA-SHA2-128F-WITH-SHA256` | `2.16.840.1.101.3.4.3.36` | `slh-dsa` |
| `SLH-DSA-SHA2-192S-WITH-SHA512` | `2.16.840.1.101.3.4.3.37` | `slh-dsa` |
| `SLH-DSA-SHA2-192F-WITH-SHA512` | `2.16.840.1.101.3.4.3.38` | `slh-dsa` |
| `SLH-DSA-SHA2-256S-WITH-SHA512` | `2.16.840.1.101.3.4.3.39` | `slh-dsa` |
| `SLH-DSA-SHA2-256F-WITH-SHA512` | `2.16.840.1.101.3.4.3.40` | `slh-dsa` |
| `SLH-DSA-SHAKE-128S-WITH-SHAKE128` | `2.16.840.1.101.3.4.3.41` | `slh-dsa` |
| `SLH-DSA-SHAKE-128F-WITH-SHAKE128` | `2.16.840.1.101.3.4.3.42` | `slh-dsa` |
| `SLH-DSA-SHAKE-192S-WITH-SHAKE256` | `2.16.840.1.101.3.4.3.43` | `slh-dsa` |
| `SLH-DSA-SHAKE-192F-WITH-SHAKE256` | `2.16.840.1.101.3.4.3.44` | `slh-dsa` |
| `SLH-DSA-SHAKE-256S-WITH-SHAKE256` | `2.16.840.1.101.3.4.3.45` | `slh-dsa` |
| `SLH-DSA-SHAKE-256F-WITH-SHAKE256` | `2.16.840.1.101.3.4.3.46` | `slh-dsa` |

The names and OIDs are those of Bouncy Castle's `SignerUtilities`, and the case of a name does not
matter. The `WITH` rows are HashSLH-DSA, which signs the hash of the message by the digest its name
gives. Each signs with fresh randomness and an empty context, as Bouncy Castle builds them.

### Params

Each row takes an `SlhDsaPrivateKey` to sign and an `SlhDsaPublicKey` to verify, of its own
parameter set; a key of another set, or of another type, is `InvalidParams`.

### Using it

- The randomness comes from the source of `DefaultAlgoBuilder::set_rand`.
- The `s` sets take long to sign, seconds on a slow machine.
- The rest is common to every signer: [Signers](Signer.md#using-it).
