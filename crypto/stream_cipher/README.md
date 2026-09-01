# Stream cipher migration

This table tracks the migration from the legacy `crates/tc_stream_cipher`
crate to independent crates under `crypto/stream_cipher`.

| Status | Target crate | Algorithms / engines |
|:------:|--------------|----------------------|
| ✅ | `tc_chacha` | ChaCha, ChaCha7539, XChaCha20 |
| ✅ | `tc_hc` | HC-128, HC-256 |
| ✅ | `tc_isaac` | ISAAC |
| ✅ | `tc_rc4` | RC4 |
| ✅ | `tc_salsa20` | Salsa20, XSalsa20 |
| ✅ | `tc_vmpc` | VMPC, VMPC-KSA3 |

Legend: ✅ completed, ⬜ TODO.
