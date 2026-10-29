# Test vectors

| File | Source | Notes |
| --- | --- | --- |
| `unsigned_request.der` | Bouncy Castle `OcspTest` (asn1), `unsignedReq` | One request for a SHA-1 `CertID`. |
| `signed_request.der` | Bouncy Castle `OcspTest` (asn1), `signedReq` | The same request, signed, with the signer's certificate. |
| `response.der` | Bouncy Castle `OcspTest` (asn1), `_response` | A successful basic response, responder by name, one revoked status without a reason. |
