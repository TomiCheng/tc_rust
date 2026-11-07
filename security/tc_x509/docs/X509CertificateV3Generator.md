# X509CertificateV3Generator

Generates version 3 X.509 certificates, after Bouncy Castle's `X509V3CertificateGenerator`.

> **Status:** a design, not yet implemented. The example below does not compile yet.

## Generating a certificate

From a new key pair to a self-signed certificate:

```rust,ignore
let oper = DefaultX509OperatorBuilder::default().build();

// Generate a pair
let mut key_gen = oper.key_pair_generator().get_by_name("RSA")?;
key_gen.init(&RsaKeyGenParams::new(2048))?;
let pair = key_gen.generate()?;

// Sign with the private key
let signer = oper.signer().get_by_name("SHA-256withRSA", pair.private())?;

// Fill in the fields, and sign
let certificate = oper
    .v3_cert_generator()
    .with_serial_number(serial)
    .with_issuer(name.clone())
    .with_validity(validity)
    .with_subject(name)
    .with_subject_public_key_info(pair.public().clone())
    .generate(&signer)?;
```

## Fields

| Set by | Required |
|---|---|
| `with_serial_number` | yes |
| `with_issuer` | yes |
| `with_validity` | yes |
| `with_subject` | yes, unless a critical subject alternative name is present |
| `with_subject_public_key_info` | yes |
| `with_extension` | no |

The signature algorithm comes from the signer, and goes into the signed part of the certificate.

## Using it

- The `with_` methods only store what they are given, so none of them fails. `generate` checks the
  fields, and reports a missing one.
- An extension may appear only once in a certificate, as RFC 5280 section 4.2 requires.
- The issuer signs: a self-signed certificate uses the private key of its own pair, and any other
  uses the private key of the issuer.
- A key that cannot sign, such as DH, can be the subject's but not the issuer's.
