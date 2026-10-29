# Test vectors

| File | Source | Notes |
| --- | --- | --- |
| `crmf_cert_req_msg.der` | Bouncy Castle `CrmfTest`, `rawMsg` | A `CertReqMsg` with a subject, an RSA key and a signature proof of possession. |
| `protected_pki_message.der` | Bouncy Castle `ProtectedMessageTest.TestVerifyBCJavaGeneratedMessage`, `ind` | A bc-java `PKIMessage`: an empty initialization response under password-based MAC protection, with one extra certificate. |
