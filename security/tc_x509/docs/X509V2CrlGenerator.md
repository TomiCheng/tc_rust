# X509V2CrlGenerator

Generates version 2 CRLs, after Bouncy Castle's `X509V2CrlGenerator`.

## Generating a CRL

A CRL signed with the CA's private key:

```rust
use std::sync::Arc;

use tc_algo::Params;
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
    generator.set_next_update_after(chrono::TimeDelta::days(7));
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
| `set_issuer`, `set_issuer_by_str`, `set_issuer_by_certificate` | yes |
| `set_this_update`, `set_this_update_by_datetime` | no: the time `generate` runs when it is not set |
| `set_next_update`, `set_next_update_by_datetime`, `set_next_update_after` | no, but RFC 5280 requires it: left out when it is not set |
| `add_crl_entry`, `add_crl_entry_with_extensions`, `add_crl` | no |
| `add_extension`, `add_crl_number`, `add_authority_key_identifier` | no, but RFC 5280 requires the CRL number and the authority key identifier |

Each `set_` has a `clear_`; entries and extensions have `remove_` and `clear_`. `reset` clears them all.
`from_crl` starts from another CRL, as Bouncy Castle's constructor with a template does, and
`add_crl` adds the entries of another CRL, to carry the last CRL's revocations into the next. The signature algorithm comes from the factory, and goes into the
signed part of the CRL.

## Using it

- The issuer is the CA that signs the CRL, so its name is the subject of the CA's certificate,
  and the factory holds the CA's private key.
- `generate` reports a field not set as `MissingField`.
- Without a this update, each CRL generated is dated when `generate` runs, so a test that needs
  the same CRL each time sets one; Bouncy Castle requires it.
- `generate` leaves the generator as it was, so it can make more than one CRL.
