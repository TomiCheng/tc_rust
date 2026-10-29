# Test vectors

All from Bouncy Castle's `ParseTest` (tsp).

| File | Field | Notes |
| --- | --- | --- |
| `sha1_request.der` | `sha1Request` | SHA-1 imprint with a nonce. |
| `ripemd160_request.der` | `ripemd160Request` | RIPEMD-160 imprint, a policy, a nonce and `certReq TRUE`. |
| `sha1_response.der` | `sha1Response` | Granted, with a token. |
| `unacceptable_policy.der` | `unacceptablePolicy` | Rejected: status text and `unacceptedPolicy`. |
| `generalized_time.der` | `generalizedTime` | Granted; the token's time has fractional seconds, which `TstInfo` rejects. |
| `v2_signing_cert_response.der` | `v2SigningCertResponse` | Granted; the signer uses `signingCertificateV2`. |
