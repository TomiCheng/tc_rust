# X509Crl

A certificate revocation list as received, after Bouncy Castle's `X509Crl`: the fields it holds,
the check of its signature, and whether a certificate is on it.

## Checking a certificate

From the bytes of a CRL and of its issuer's certificate to whether a certificate is revoked:

```rust
use tc_x509::cert::X509Certificate;
use tc_x509::crl::X509Crl;
use tc_x509::{DefaultX509OperatorBuilder, X509Error, X509OperatorBuilder};

fn main() -> Result<(), X509Error> {
    let oper = DefaultX509OperatorBuilder::default().build();
#   let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/crl/");
#   let read = |name: &str| std::fs::read(format!("{dir}{name}")).unwrap();
#   let (ca_bytes, crl_bytes, cert_bytes) = (read("ca.der"), read("crl.der"), read("revoked.der"));

    // The CRL, its issuer, and the certificate to check
    let ca = X509Certificate::decode(&ca_bytes)?;
    let crl = X509Crl::decode(&crl_bytes)?;
    let certificate = X509Certificate::decode(&cert_bytes)?;

    // Check the CRL is the issuer's, with the issuer's key
    let key = oper.spki().decode(ca.subject_public_key_info())?;
    crl.verify(oper.verifier_factory_provider(key.into()).as_ref())?;

    // Is the certificate on it, and since when
    if let Some(entry) = crl.revoked_certificate_of(&certificate) {
        println!("revoked on {}", entry.revocation_date());
    }
    assert!(crl.is_revoked(&certificate));
    Ok(())
}
```

Only the signature depends on the algorithm, so only it goes through the operator. The CRL is a
plain type that holds the fields.

## The entries

An `X509CrlEntry` is one revoked certificate. It borrows the entry from the CRL rather than
copying it, as a CRL may list many, so it lives no longer than the CRL:

```rust,ignore
for entry in crl.revoked_certificates() {
    println!("{} revoked on {}", entry.serial_number(), entry.revocation_date());
}
```

To keep an entry after the CRL is gone, keep `entry.revoked_certificate().clone()`, the ASN.1
structure it borrows.

An indirect CRL (RFC 5280 section 5.2.5) lists certificates of issuers other than its own. The
certificateIssuer extension of an entry names the issuer of that entry and of the entries after
it, until another entry names a new one, so the CRL works the issuer out as it goes through them,
and an entry gives it as `certificate_issuer`. It is `None` for a certificate of the CRL's own
issuer, and in a CRL that is not indirect.

## Methods

| Method | Bouncy Castle |
|---|---|
| `decode`, `decode_from`, `new` | the constructors |
| `encode`, `encode_to` | `GetEncoded` |
| `version`, `issuer`, `this_update`, `next_update`, `extensions` | `Version`, `IssuerDN`, `ThisUpdate`, `NextUpdate`, the extensions |
| `revoked_certificate` | `GetRevokedCertificate(BigInteger)` |
| `revoked_certificate_of`, `is_revoked` | `GetRevokedCertificate(X509Certificate)`, `IsRevoked` |
| `revoked_certificates` | `GetRevokedCertificates` |
| `is_indirect` | `IsIndirect` |
| `tbs_cert_list`, `signature`, `signature_algorithm` | `GetTbsCertList`, `GetSignature`, `SignatureAlgorithm` |
| `is_signature_valid`, `verify` | `IsSignatureValid`, `Verify` |
| `certificate_list` | `CertificateList` |

And of an entry:

| Method | Bouncy Castle |
|---|---|
| `serial_number`, `revocation_date`, `extensions` | `SerialNumber`, `RevocationDate`, the extensions |
| `certificate_issuer` | `GetCertificateIssuer` |
| `revoked_certificate` | `CrlEntry` |

## Using it

- Check the signature first: a CRL is only as good as the key it verifies with, the key of the
  CRL's issuer, which is the issuer of the certificates it lists unless it is indirect.
- `is_revoked` matches the issuer of the certificate as well as its serial number, since a serial
  number is unique only within its issuer. An entry with the reason `removeFromCRL`, which a
  delta CRL gives a certificate whose hold is lifted, does not count as revoked, and a reason
  that does not decode does.
- The first lookup builds an index of the entries by serial number, so each one after it is a
  hash rather than a pass over every entry. `revoked_certificate` matches the serial number alone,
  so prefer `revoked_certificate_of` for an indirect CRL.
- A certificate of another issuer is not on a CRL that is not indirect, whatever its serial number.
- `revoked_certificates` is empty for a CRL that lists none, where Bouncy Castle gives null.
- Only the signature and the entries are checked here. Whether the CRL is current, by
  `this_update` and `next_update`, and whether its scope covers the certificate, by its
  issuingDistributionPoint, are left to the caller.
- `new` is `Asn1` when the issuingDistributionPoint extension does not decode, as it is read to
  know whether the CRL is indirect. A certificateIssuer extension that does not decode gives no
  issuer, as Bouncy Castle does.
