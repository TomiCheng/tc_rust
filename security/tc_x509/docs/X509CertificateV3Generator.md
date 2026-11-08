# X509CertificateV3Generator

Generates version 3 X.509 certificates, after Bouncy Castle's `X509V3CertificateGenerator`.

## Generating a certificate

From a new key pair to a self-signed certificate:

```rust
use tc_asn1_x509::ext::{BasicConstraints, KeyUsage};
use tc_x509::cert::X509V3CertificateGenerator;
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
    let mut generator = X509V3CertificateGenerator::new();
    generator.set_issuer_by_str("CN=My CA,O=Acme")?;
    generator.set_subject_by_str("CN=My CA,O=Acme")?;
    generator.set_validity_days(365)?;
    generator.set_subject_public_key_info(spki);
    generator.add_basic_constraints(BasicConstraints::ca(None))?;
    generator.add_key_usage(KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN)?;
    let certificate = generator.generate(factory.as_ref())?;

    assert_eq!(certificate.subject().to_string(), "CN=My CA,O=Acme");
    Ok(())
}
```

Only two steps depend on the algorithm, the public key and the signature, so only they go through
the operator. The generator is a plain type that holds the fields.

To sign more than one thing with the same private key, such as a certificate and a CRL, give each
factory a clone of the `Arc` that holds it. A clone of an `Arc` is another reference to the same
key, not a copy of it:

```rust,ignore
let private: Arc<dyn Params> = private.into();
let cert_factory = oper.signature_factory("SHA-256withRSA", private.clone())?;
let crl_factory = oper.signature_factory("SHA-256withRSA", private)?;
```

## Fields

| Set by | Required |
|---|---|
| `set_serial_number` | no: a random one of 16 bytes is made when it is not set |
| `set_issuer`, `set_issuer_by_str` | yes |
| `set_validity`, `set_validity_days`, `set_not_before`, `set_not_after` | yes |
| `set_subject`, `set_subject_by_str` | yes, unless a critical subject alternative name is present |
| `set_subject_public_key_info` | yes |
| `add_extension`, `add_basic_constraints`, `add_key_usage`, `add_subject_alt_name` | no |

Each `set_` has a `clear_`, and `reset` clears them all. `from_certificate` starts from another
certificate, as Bouncy Castle's constructor with a template does. The signature algorithm comes
from the factory, and goes into the signed part of the certificate.

## Using it

- `oper.spki().encode` takes any public key a row knows, RSA among the built-in ones. A private key
  is `NotPublicKey`, and a key no row knows is `UnknownPublicKey`.
- `set_serial_number` is `InvalidSerialNumber` unless the number is positive, as Bouncy Castle
  checks, and `add_extension` is `DuplicateExtension` for an OID already added. `generate`
  reports a field not set as `MissingField`, and an end of the validity before its start.
- Without a serial number, each certificate generated gets a new one, so a test that needs the
  same certificate each time sets one. A template brings its serial number, so clear it for a new
  certificate from the same issuer.
- `generate` leaves the generator as it was, so it can make more than one certificate.
- The issuer signs: a self-signed certificate uses the private key of its own pair, and any other
  uses the private key of the issuer.
- A key that cannot sign, such as DH, can be the subject's but not the issuer's.
