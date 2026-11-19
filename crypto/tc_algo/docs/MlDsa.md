# ML-DSA

ML-DSA, FIPS 204, is a signature over module lattices, made to resist a quantum computer. Its three
parameter sets trade the size of keys and signatures for strength.

The `ml-dsa` feature of `tc_algo` has the rows.

## Key pairs

A parameter set and a new pair:

```rust
use tc_algo::params::key::MlDsaParameters;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("ML-DSA", &MlDsaParameters::ML_DSA_65)?;

    let (_public, _private) = pair.into_parts();
    Ok(())
}
```

### Algorithms

| Name | Feature | Params | Public key | Private key |
|---|---|---|---|---|
| `ML-DSA` | `ml-dsa` | `MlDsaParameters` | `MlDsaPublicKey` | `MlDsaPrivateKey` |

The name is that of Bouncy Castle's `GeneratorUtilities`, and its case does not matter.

### Params

`MlDsaParameters::ML_DSA_44`, `ML_DSA_65` or `ML_DSA_87`. There is no default, so `generate_by_name`
gives `NotInitialized`, and any other type is `InvalidParams`.

## Signing

From a new pair to a verified signature:

```rust
use tc_algo::params::key::MlDsaParameters;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "ML-DSA-65";
    let message = b"attack at dawn";

    // Generate a pair
    let pair = algo
        .key_pair_generator()
        .generate_by_name_with("ML-DSA", &MlDsaParameters::ML_DSA_65)?;

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
| `ML-DSA-44` | `2.16.840.1.101.3.4.3.17` | `ml-dsa` |
| `ML-DSA-65` | `2.16.840.1.101.3.4.3.18` | `ml-dsa` |
| `ML-DSA-87` | `2.16.840.1.101.3.4.3.19` | `ml-dsa` |
| `ML-DSA-44-WITH-SHA512` | `2.16.840.1.101.3.4.3.32` | `ml-dsa` |
| `ML-DSA-65-WITH-SHA512` | `2.16.840.1.101.3.4.3.33` | `ml-dsa` |
| `ML-DSA-87-WITH-SHA512` | `2.16.840.1.101.3.4.3.34` | `ml-dsa` |

The names and OIDs are those of Bouncy Castle's `SignerUtilities`, and the case of a name does not
matter. The `WITH-SHA512` rows are HashML-DSA, which signs the SHA-512 hash of the message. Each
signs with fresh randomness, hedged, and an empty context, as Bouncy Castle builds them.

### Params

Each row takes an `MlDsaPrivateKey` to sign and an `MlDsaPublicKey` to verify, of its own parameter
set; a key of another set, or of another type, is `InvalidParams`.

### Using it

- The randomness comes from the source of `DefaultAlgoBuilder::set_rand`.
- The rest is common to every signer: [Signers](Signer.md#using-it).
