# Stores and selectors

The `store` module finds certificates, CRLs and attribute certificates among many, and tells
whether any of many CRLs revokes a certificate. A collection of them is a `Vec` or any iterator;
there is no store trait.

## Selectors

A selector holds criteria and `matches` a value against them; a criterion not set selects every
value. It works on any `Vec` or iterator, `certs.iter().filter(|c| selector.matches(c))`, and a
condition of one's own is a closure beside it.

- `X509CertSelector`, after Bouncy Castle's `X509CertStoreSelector`: serial number, issuer,
  subject, a time the certificate must be valid at, and the subject and authority key
  identifiers.
- `X509CrlSelector`, after `X509CrlStoreSelector`: issuers, any one of which matches, a time the
  CRL must be in force at, and a range of CRL numbers.
- `X509AttrCertSelector`, after `X509AttrCertStoreSelector`: serial number, issuer and a time of
  validity.

Names are compared by equivalence, as RFC 5280 matches them, so a selector by issuer or subject
finds a name written in another case or with other spacing.

## Stores

- [X509CertificateStore](X509CertificateStore.md): certificates found by an `X509CertSelector`,
  through an index of serial numbers and subject key identifiers, for a store looked up again and
  again, as a path builder does.
- [X509CrlStore](X509CrlStore.md): CRLs of many issuers, asked whether any of them revokes a
  certificate.
