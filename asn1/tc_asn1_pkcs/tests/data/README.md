# Test vectors

| File | Source | Notes |
| --- | --- | --- |
| `pkcs10_req1.der` | Bouncy Castle `PKCS10Test`, `req1` | A DER certification request. |
| `pkcs10_req2.der` | Bouncy Castle `PKCS10Test`, `req2` | A DER certification request with UTF8String name values. |
| `pkcs12.ber` | Bouncy Castle `Pkcs12Test`, `pkcs12` | Indefinite-length BER: a shrouded key bag and password-encrypted certificates, with MAC data. Decode it with `decode`, not `decode_der`. |
