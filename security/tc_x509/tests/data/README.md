# Test vectors

- `rfc8410.der`: RFC 8410 §10.2, the example X25519 certificate. Self-issued, signed with
  Ed25519, CN=IETF Test Demo, valid 2016-08-01 to 2040-12-31. Extensions: basicConstraints,
  keyUsage keyAgreement, subjectKeyIdentifier. BER rather than DER. TBSCertificate is at
  `[4..230]`, the signature octets at `[240..304]`.
- `crl/`: made with `openssl` 3. `ca.der` is a self-signed RSA 2048 CA, CN=Test CA, which issued
  `revoked.der` (CN=revoked) and `good.der` (CN=good). `crl.der` is its v2 CRL, signed with
  SHA-256withRSA, with a CRL number and one entry, `revoked.der`'s, with reason keyCompromise.
  `bundle.p7b` is a PKCS #7 bundle of the three certificates and the CRL, made with
  `openssl crl2pkcs7 -in crl.pem -certfile ca.pem -certfile good.pem -certfile revoked.pem
  -outform DER`.
  `chain.pem` is the same in PEM, `openssl x509` and `openssl crl` output put one after
  another: `ca`, the CRL, `good`, `revoked`.
  `bundle.pem` is `bundle.p7b` in PEM, labelled PKCS7, by `openssl pkcs7 -outform PEM`.
