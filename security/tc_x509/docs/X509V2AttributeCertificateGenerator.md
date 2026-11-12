# X509V2AttributeCertificateGenerator

Generates attribute certificates (RFC 5755), after Bouncy Castle's
`X509V2AttributeCertificateGenerator`. An attribute certificate binds attributes, such as roles
or clearances, to the holder of a public-key certificate rather than to a key of its own. An
attribute authority issues it and signs it, so the attributes can change without a new
public-key certificate.

## Generating an attribute certificate

An attribute authority gives the holder of a certificate a role:

```rust
use tc_asn1::Asn1Oid;
use tc_asn1_x500::{Attribute, DirectoryString};
use tc_x509::cert::X509V2AttributeCertificateGenerator;
use tc_x509::operator::params::RsaKeyGenParams;
use tc_x509::{DefaultX509OperatorBuilder, X509OperatorBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let oper = DefaultX509OperatorBuilder::default().build();

    // The attribute authority signs with its private key
    let mut key_gen = oper.key_pair_generator().get_by_name("RSA")?;
    key_gen.init(&RsaKeyGenParams::new(2048))?;
    let (_, private) = key_gen.generate()?.into_parts();
    let factory = oper.signature_factory("SHA-256withRSA", private.into())?;

    // The role, an attribute of type 2.5.4.72
    let role: Asn1Oid = "2.5.4.72".parse()?;
    let operator_role = Attribute::new(role, vec![DirectoryString::new("operator")?.into()])?;

    // Fill in the fields, and sign
    let mut generator = X509V2AttributeCertificateGenerator::new();
    generator.set_holder_by_str("CN=Alice,O=Acme")?;
    generator.set_issuer_by_str("CN=Attribute Authority,O=Acme")?;
    generator.set_validity_days(30)?;
    generator.add_attribute(operator_role)?;
    let certificate = generator.generate(factory.as_ref())?;

    assert_eq!(certificate.attributes().len(), 1);
    Ok(())
}
```

Only the signature depends on the algorithm, so only it goes through the operator. An attribute
certificate holds no public key of its own.

## Fields

| Set by | Required |
|---|---|
| `set_holder`, `set_holder_by_certificate`, `set_holder_by_name`, `set_holder_by_str` | yes |
| `set_issuer`, `set_issuer_by_name`, `set_issuer_by_str` | yes |
| `set_serial_number` | no: a random one of 16 bytes is made when it is not set |
| `set_validity`, `set_validity_days`, `set_validity_by_datetime`, `set_not_before`, `set_not_after` | yes |
| `add_attribute` | yes, at least one |
| `set_issuer_unique_id` | no |
| `add_extension` | no |

Each `set_` has a `clear_`; attributes and extensions have `remove_` and `clear_`. `reset` clears
them all. The signature algorithm comes from the factory, and goes into the signed part of the
attribute certificate.

## Using it

- `set_holder_by_certificate` names the holder by the issuer and serial number of their
  public-key certificate, the form RFC 5755 recommends; `set_holder_by_name` and
  `set_holder_by_str` name them by their name.
- The issuer is the attribute authority. `set_issuer_by_name` and `set_issuer_by_str` give its
  name in the version 2 form RFC 5755 requires.
- `add_attribute` is `DuplicateAttribute` for a type already added, as RFC 5755 allows each type
  only once; put more values in the one attribute instead. `add_extension` is
  `DuplicateExtension` for an OID already added.
- `set_serial_number` is `InvalidSerialNumber` unless the number is positive. `generate` reports a
  field not set as `MissingField`, no attribute among them, and an end of the validity before its
  start.
- `generate` leaves the generator as it was, so it can make more than one attribute certificate.
