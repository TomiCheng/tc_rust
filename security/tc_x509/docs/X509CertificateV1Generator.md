# X509CertificateV1Generator

Generates version 1 X.509 certificates, after Bouncy Castle's `X509V1CertificateGenerator`. A
version 1 certificate has the fields of a version 3 one but no extensions, so it cannot say that
it is a CA, what its key is for, or which other names it goes by. Use it only for a system that
still expects version 1; anything else takes `X509V3CertificateGenerator`.

## Generating a certificate

From a new key pair to a self-signed version 1 certificate:

```rust
use tc_asn1_x509::cert::Version;
use tc_x509::cert::X509V1CertificateGenerator;
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509OperatorBuilder};

fn main() -> Result<(), X509Error> {
    let oper = DefaultX509OperatorBuilder::default().build();

    // Generate a pair
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA")?;
    key_gen.init(&RsaKeyGenParams::new(2048))?;
    let (public, private) = key_gen.generate()?.into_parts();

    // The public key, as a certificate holds it
    let spki = oper.spki().encode(public.as_ref())?;

    // Sign with the private key
    let factory = oper.signature_factory("SHA-256withRSA", private.into())?;

    // Fill in the fields, and sign
    let mut generator = X509V1CertificateGenerator::new();
    generator.set_issuer_by_str("CN=Legacy,O=Acme")?;
    generator.set_subject_by_str("CN=Legacy,O=Acme")?;
    generator.set_validity_days(365)?;
    generator.set_subject_public_key_info(spki);
    let certificate = generator.generate(factory.as_ref())?;

    assert_eq!(certificate.version(), Version::V1);
    assert!(certificate.extensions().is_none());
    Ok(())
}
```

Only two steps depend on the algorithm, the public key and the signature, so only they go through
the operator. The generator is a plain type that holds the fields.

## Fields

| Set by | Required |
|---|---|
| `set_serial_number` | no: a random one of 16 bytes is made when it is not set |
| `set_issuer`, `set_issuer_by_str` | yes |
| `set_validity`, `set_validity_days`, `set_validity_by_datetime`, `set_not_before`, `set_not_after` | yes |
| `set_subject`, `set_subject_by_str` | yes |
| `set_subject_public_key_info` | yes |

Each `set_` has a `clear_`, and `reset` clears them all. There is no `add_extension`: a version 1
certificate has none. The signature algorithm comes from the factory, and goes into the signed
part of the certificate.

## Using it

- `set_serial_number` is `InvalidSerialNumber` unless the number is positive, as Bouncy Castle
  checks. `generate` reports a field not set as `MissingField`, and an end of the validity before
  its start.
- Without a serial number, each certificate generated gets a new one, so a test that needs the
  same certificate each time sets one.
- `generate` leaves the generator as it was, so it can make more than one certificate.
- The issuer signs: a self-signed certificate uses the private key of its own pair, and any other
  uses the private key of the issuer.
- A version 1 certificate cannot carry a subject alternative name, so its subject is always
  required, where version 3 lets a critical subject alternative name stand in for it.
