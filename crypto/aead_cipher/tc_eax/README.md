# tc_eax

`tc_eax` implements EAX authenticated encryption over any 8- or 16-byte block
cipher that implements the shared `tc_cipher` contracts.

- EAX combines CTR encryption with domain-separated CMAC authentication.
- Authentication tags may be 4 bytes through one full cipher block.
- Nonces may have any length, but must be unique for each key used to encrypt.
- AAD must be supplied before the first non-empty message input.
- Full blocks may be emitted during `process_bytes`; callers must not release
  decrypted plaintext until `do_final` verifies the tag.
- The default `alloc` feature stores initial AAD and the nonce-reuse guard. The
  crate still compiles as `no_std` with that feature disabled, without exposing
  the engine.

Run its tests from the workspace root:

```bash
cargo test -p tc_eax --locked
```
