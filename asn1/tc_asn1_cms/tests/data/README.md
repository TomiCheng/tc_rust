# Test vectors

| File | Source | Notes |
| --- | --- | --- |
| `rfc8410.der` | RFC 8410 §10.2, the example X25519 certificate | Self-issued, signed with Ed25519, CN=IETF Test Demo. BER rather than DER: two extensions write `critical FALSE` and basicConstraints writes its DEFAULT, so decode it with `decode`, not `decode_der`. |
