# X509CertificateStore

Certificates found by an `X509CertSelector`, after Bouncy Castle's store of certificates. Any
`Vec` takes a selector too, but passes over every certificate; the store answers through an
index, so a store of hundreds of thousands of certificates looked up again and again costs a hash
and a few comparisons each time.

## Finding certificates

```rust
use tc_x509::cert::X509Certificate;
use tc_x509::store::{X509CertSelector, X509CertificateStore};

let mut store = X509CertificateStore::default();
for path in ["ca.der", "good.der", "revoked.der"] {
    store.add(X509Certificate::decode(&std::fs::read(path)?)?);
}

// One certificate, by its issuer and serial number, through the index
let wanted = &store.certificates()[1];
let selector = X509CertSelector::new()
    .with_issuer(wanted.issuer().clone())
    .with_serial_number(wanted.serial_number().clone());
let found = store.find(&selector).expect("the certificate");

// Its issuer, by subject, as a path builder looks for it
let selector = X509CertSelector::new().with_subject(found.issuer().clone());
for issuer in store.select(&selector) {
    println!("{}", issuer.subject());
}
```

## Methods

| Method | Does |
|---|---|
| `new`, `from_iter`, `default` | a store of certificates, or an empty one |
| `add`, `extend` | adds certificates, in the order added |
| `certificates` | every certificate, in the order added |
| `select` | the certificates a selector selects, in the order added |
| `find` | the first of them |

## Using it

- A selector with a serial number is answered through the index of serial numbers; one with a
  subject key identifier and no serial number, through the index of key identifiers; any other
  by a pass over every certificate. Every candidate is still checked with `matches`, so the
  result is the same either way.
- Names are not indexed: they match by equivalence rather than by their octets, so a key of
  octets would miss an equivalent name. A selector by issuer or subject alone is a pass.
- The index is built on the first selection after the store last changed; `add` and `extend`
  drop it, to be built again.
- The store holds certificates, not trust: a certificate found in it is checked as any other is.
