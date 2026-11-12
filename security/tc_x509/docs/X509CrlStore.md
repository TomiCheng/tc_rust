# X509CrlStore

CRLs of any number of issuers, or several of one, asked whether any of them revokes a
certificate.

## Checking a certificate

```rust
use tc_x509::cert::X509Certificate;
use tc_x509::crl::X509Crl;
use tc_x509::store::X509CrlStore;

// The CRLs, each verified with the key of its issuer before it is added
let mut store = X509CrlStore::default();
for path in ["ca1.crl", "ca2.crl"] {
    let crl = X509Crl::decode(&std::fs::read(path)?)?;
    // crl.verify(...)?;
    store.add(crl);
}

let certificate = X509Certificate::decode(&std::fs::read("server.der")?)?;
if let Some((crl, entry)) = store.revoked_certificate_of(&certificate) {
    println!("revoked by {} on {}", crl.issuer(), entry.revocation_date());
}
println!("revoked: {}", store.is_revoked(&certificate));
```

## Methods

| Method | Does |
|---|---|
| `new`, `from_iter`, `default` | a store of CRLs, or an empty one |
| `add`, `extend` | adds CRLs, in the order added |
| `crls` | every CRL, in the order added |
| `is_revoked` | whether any CRL lists the certificate as revoked |
| `revoked_certificate_of` | the first CRL listing the certificate, with its entry |

## Using it

- Each CRL answers as `X509Crl::is_revoked` does. One of another issuer is passed over after a
  comparison of names; one that applies looks the certificate up in its own index of serial
  numbers, built on its first lookup. A check costs a name comparison per CRL and a hash for the
  few that apply.
- `is_revoked` does not count an entry with the reason `removeFromCRL`; `revoked_certificate_of`
  finds it too, for a caller that reads the reason.
- The store does not verify the CRLs: each is the caller's to verify with the key of its issuer
  before adding it, since a CRL is only as good as that key.
- A delta CRL is read on its own, not merged with its base CRL, and whether a CRL is current, by
  its update times, is left to the caller; an `X509CrlSelector` with a time picks the CRLs in
  force.
