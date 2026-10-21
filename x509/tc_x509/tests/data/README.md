# Test vectors

- `rfc8410.der`: RFC 8410 §10.2, the example X25519 certificate. Self-issued, signed with
  Ed25519, CN=IETF Test Demo, valid 2016-08-01 to 2040-12-31. Extensions: basicConstraints,
  keyUsage keyAgreement, subjectKeyIdentifier. BER rather than DER. TBSCertificate is at
  `[4..230]`, the signature octets at `[240..304]`.
