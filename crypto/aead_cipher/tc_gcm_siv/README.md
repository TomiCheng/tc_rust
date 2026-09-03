# tc_gcm_siv

`tc_gcm_siv` implements the allocation-backed AES-GCM-SIV packet construction
from RFC 8452 over a caller-selected 16-byte block cipher.

- Master keys are 16 or 32 bytes.
- Nonces are exactly 12 bytes.
- Authentication tags are exactly 16 bytes.
- AAD must be supplied before the first non-empty message input.
- `process_bytes` buffers input and returns zero; `do_final` emits the packet.
- Decryption verifies the tag before copying plaintext to caller output.
- `reset` starts another packet with the initialized key, nonce, and initial
  AAD. GCM-SIV is nonce-misuse resistant, but callers should still use unique
  nonces because reuse reveals whether messages are equal.
- AAD and plaintext are each limited to 2^36 bytes by RFC 8452.
- POLYVAL is an internal portable implementation. There are no public
  multiplier or exponentiator strategy interfaces.
- The default `alloc` feature is required by the engine; the crate itself still
  compiles as `no_std` when that feature is disabled.

Run its tests from the workspace root:

```bash
cargo test -p tc_gcm_siv --locked
```
