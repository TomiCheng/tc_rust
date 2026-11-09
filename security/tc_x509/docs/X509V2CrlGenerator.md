# X509V2CrlGenerator

Generates version 2 CRLs, after Bouncy Castle's `X509V2CrlGenerator`.

## Generating a CRL

A CRL signed with the CA's private key:

```rust
use std::sync::Arc;

use tc_algo_v2::Params;
use tc_x509::crl::X509V2CrlGenerator;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509OperatorBuilder};

// The CA's private key, from wherever it is kept
fn get_ca_private_key() -> Result<Arc<dyn Params>, X509Error> {
#   let oper = DefaultX509OperatorBuilder::default().build();
#   let mut key_gen = oper.key_pair_generator().get_by_name("RSA")?;
#   key_gen.init(&tc_x509::operator::params::RsaKeyGenParams::new(2048))?;
#   Ok(key_gen.generate()?.into_parts().1.into())
    // ...
}

fn main() -> Result<(), X509Error> {
    let oper = DefaultX509OperatorBuilder::default().build();

    // Sign with the CA's private key
    let factory = oper.signature_factory("SHA-256withRSA", get_ca_private_key()?)?;

    // Fill in the fields, and sign
    let mut generator = X509V2CrlGenerator::new();
    generator.set_issuer_by_str("CN=My CA,O=Acme")?;
    generator.set_this_update_by_datetime(chrono::Utc::now())?;
    let crl = generator.generate(factory.as_ref())?;

    assert_eq!(crl.issuer().to_string(), "CN=My CA,O=Acme");
    Ok(())
}
```

Only the signature depends on the algorithm, so only it goes through the operator. The generator
is a plain type that holds the fields.

## Fields

| Set by | Required |
|---|---|
| `set_issuer`, `set_issuer_by_str` | yes |
| `set_this_update`, `set_this_update_by_datetime` | yes |

Each `set_` has a `clear_`. The signature algorithm comes from the factory, and goes into the
signed part of the CRL.

## Using it

- The issuer is the CA that signs the CRL, so its name is the subject of the CA's certificate,
  and the factory holds the CA's private key.
- `generate` reports a field not set as `MissingField`.
- `generate` leaves the generator as it was, so it can make more than one CRL.
