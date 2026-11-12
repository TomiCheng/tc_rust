# Generating

Certificates, CRLs and attribute certificates are made by generators. A generator is a plain type
that holds the fields: each is set with a `set_` method, cleared with a `clear_` one, and
`generate` signs them all into the finished value. What depends on an algorithm comes from an
`X509Operator`:

1. a key pair, from `key_pair_generator`;
2. the public key as a certificate holds it, from `spki`;
3. the signature, from a `signature_factory` that holds the private key of the issuer.

The same signature factory signs every certificate and CRL of an issuer.

## What can be generated

- [`X509V3CertificateGenerator`](X509CertificateV3Generator.md): version 3 certificates, the
  ones in use today, with extensions such as basic constraints, key usage and subject
  alternative names. A CA certificate, self-signed or issued by another CA, and an end-entity
  certificate are both made with it.
- [`X509V1CertificateGenerator`](X509CertificateV1Generator.md): version 1 certificates, with
  the fields of version 3 but no extensions, for systems that still expect them.
- [`X509V2CrlGenerator`](X509V2CrlGenerator.md): version 2 CRLs, the certificates an issuer has
  revoked, each with its serial number, revocation date and reason, and the CRL's extensions such
  as its CRL number.
- [`X509V2AttributeCertificateGenerator`](X509V2AttributeCertificateGenerator.md): attribute
  certificates, which bind attributes such as roles to the holder of a certificate, issued by an
  attribute authority.

## Extensions made for you

The `extension` module makes the extensions that link a certificate to its issuer:
`subject_key_identifier` from the certificate's public key, and `authority_key_identifier` from
the issuer's certificate. RFC 5280 wants the first on every CA certificate and the second on
every certificate but a self-signed root.
