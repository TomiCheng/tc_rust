# Test vectors

| File | Source | Notes |
| --- | --- | --- |
| `bc_ssleay_certificate.der` | Bouncy Castle `RequestedCertificateUnitTest`, `certBytes` | An old SSLeay v1 certificate whose outer `signatureAlgorithm` (md5) differs from the TBS `signature` (md5WithRSAEncryption), so tc_asn1_x509 rejects it. |
| `rfc8410.der` | RFC 8410 §10.2, the example X25519 certificate | BER rather than DER, so decode it with `decode`. |
