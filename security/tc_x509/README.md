# tc_x509

X.509 certificates, CRLs and attribute certificates, after Bouncy Castle's
`Org.BouncyCastle.X509`, over the ASN.1 structures of `tc_asn1_x509`. It generates and signs
them, verifies their signatures, encodes and decodes them, reads them from DER, PEM and PKCS #7
files, finds them among many and tells whether a certificate is revoked.

Everything that depends on an algorithm, keys, signing and verifying, goes through an
`X509Operator`, which finds the algorithms by name. The certificate types and the generators are
plain types that hold their fields.

## Documentation

- [Core types](docs/Core.md): `X509Certificate`, `X509Crl`, `X509AttributeCertificate` and the
  `X509Operator` that holds the algorithms; reading a certificate's public key and checking a
  certificate.
- [Generating](docs/Generating.md): version 3 and version 1 certificates, CRLs and attribute
  certificates.
- [Encoding, decoding and parsing](docs/EncodingAndParsing.md): DER in and out, and reading DER,
  PEM and PKCS #7 files with the parsers of the operator.
- [Stores and selectors](docs/StoresAndSelectors.md): finding certificates, CRLs and attribute
  certificates among many, and checking a certificate against many CRLs.
