# tc_ocb

`tc_ocb` provides allocation-backed OCB3 authenticated encryption over a
caller-selected 16-byte block cipher. It implements RFC 7253 and uses the
shared `AeadCipher`, `AeadCipherInit`, and `AeadBlockCipher` contracts.

`OcbBlockCipher::new()` receives two instances of the same block-cipher
algorithm. OCB uses the first in the encryption direction for hashing and
offset generation; the second processes message blocks in the requested
direction.

Parameters are supplied with `tc_params::AeadBlockParams` or any caller type
implementing `KeyParams`, `IvParams`, `InitialAadParams`, and `MacSizeParams`.
The nonce may contain at most 15 bytes, and the tag size is 8 through 16 bytes.

The current engine buffers a complete packet and therefore requires `alloc`.
It does not expose decrypted plaintext until authentication succeeds.

## Verification

```bash
cargo test -p tc_ocb --locked
cargo test -p tc_ocb --release --locked
cargo clippy -p tc_ocb --all-targets --no-deps --locked -- -D warnings
```
