# tc_kccm

`tc_kccm` provides the DSTU 7624 KCCM authenticated-encryption construction.
It is not the NIST CCM mode provided by `tc_ccm`.

`KccmBlockCipher<C, NB>` supports DSTU 7624 block sizes of 16, 32, and 64
bytes. `NB` may be 4, 6, or 8; the default is 4. Message data and associated
data must contain complete cipher blocks. The supported tag sizes are 8, 16,
32, 48, and 64 bytes, not exceeding the selected cipher's block size.

The engine buffers complete packets and therefore uses the default `alloc`
feature. Decryption verifies the tag before copying plaintext to caller
memory.

## Verification

```bash
cargo test -p tc_kccm --locked
cargo test -p tc_kccm --release --locked
cargo clippy -p tc_kccm --all-targets --no-deps --locked -- -D warnings
```
