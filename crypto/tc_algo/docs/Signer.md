# Signers

A signature is made with a private key, and anyone with the public key can check it: it shows that
the message was not changed and that it came from the holder of the private key. Unlike a MAC, the
two sides do not share a secret.

From a new pair to a verified signature, with ECDSA over SHA-256 on P-256. The `ecdsa`, `fp-custom`
and `sha` features of `tc_algo` have the row.

```rust
use tc_algo::params::generate::EcKeyGenParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "SHA-256withECDSA";
    let message = b"attack at dawn";

    // Generate a pair
    let params = EcKeyGenParams::new("P-256");
    let pair = algo.key_pair_generator().generate_by_name_with("EC", &params)?;

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

## Algorithms

The names and OIDs are those of Bouncy Castle's `SignerUtilities`, and the case of a name does not
matter. Most rows pair a scheme with a digest, named as `SHA-256withECDSA`, and need the feature of
the scheme and of the digest, as `ecdsa` and `sha`.

- **[RSA](Rsa.md#signing)**: PKCS#1 v1.5, PSS, X9.31 and ISO 9796-2, with the `rsa` feature.
- **[EC](Ec.md#signing)**: ECDSA, with its signature in DER or plain, with the `ecdsa` feature, and
  ECNR, with the `ecnr` feature.
- **[SM2](Sm2.md#signing)**: over SM3 or SHA-256, with the `sm2` feature.
- **[EdDSA](EdDSA.md#signing)**: Ed25519 and Ed448, with the `cfrg-curves` feature.
- **[ML-DSA](MlDsa.md#signing)** and **[SLH-DSA](SlhDsa.md#signing)**: the signatures of FIPS 204
  and 205, made to resist a quantum computer, with the `ml-dsa` and `slh-dsa` features.
- **[DSA](Dsa.md#signing)**, with the `dsa` feature, **[GOST R 34.10-94](Gost3410.md#signing)**, with
  the `gost3410` feature, and GOST R 34.10-2001 and -2012 over EC keys, with the `ecgost3410`
  feature: for old data and the formats that name them.

DSTU 4145 is not here: Bouncy Castle's `SignerUtilities` does not name it.

## Params

A private key signs, and a public key verifies: the key tells the direction. Each family takes the
keys of its key pair generator, and any other type is `InvalidParams`.

## Using it

- `get_by_name` and `get_by_oid` give a `Signer`, which is a `Signer` and a `SignerInit` of
  `tc_signer` with `AlgoError` for its errors, so code written for those traits takes it as it
  is.
- **Look at the answer of `verify_signature`.** A wrong signature gives `Ok(false)`, not an error, so
  a bare `?` on the call lets a forged message through.
- A message can come in pieces, over several calls of `update`.
- `sign` gives the signature in a `Vec`. `generate_signature` writes it into a buffer of
  `max_signature_size` bytes, and one too short is `DataLength`.
- `sign`, `generate_signature` and `verify_signature` start the next message under the same key.
  `reset` discards the message so far.
- `update`, `generate_signature` and `verify_signature` give `NotInitialized` before an `init` that
  succeeded. So do `generate_signature` with a public key and `verify_signature` with a private one.
- The randomness of a signature, such as the k of ECDSA or the salt of PSS, comes from the source of
  `DefaultAlgoBuilder::set_rand`.
