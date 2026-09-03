# tc_gcm

`tc_gcm` provides the generic `GcmBlockCipher<C>` authenticated-encryption
construction for 16-byte block ciphers.

The first implementation uses an internal portable GHASH multiplier. It does
not expose Bouncy Castle's obsolete `IGcmMultiplier`, `IGcmExponentiator`, or
`BasicGcmExponentiator` extension points. Hardware-accelerated GHASH can be
added later without changing the public API.

## Parameters and behavior

Initialization accepts any parameter type implementing `KeyParams`,
`IvParams`, `InitialAadParams`, and `MacSizeParams`.

- Nonces may have any non-zero length; 12-byte nonces use the standard fast
  path.
- Authentication tags may contain 4 through 16 bytes.
- AAD must be supplied before the first non-empty message input. Later AAD is
  rejected with `AeadError::AadAfterData`, so no exponentiator is required.
- Encryption rejects reuse of the same key and nonce.
- The implementation requires `alloc` to retain the last key and nonce for
  reuse detection, but does not require `std`.

## Verification

The tests cover NIST and Bouncy Castle vectors, 128-, 192-, and 256-bit AES
keys, 12-byte and non-12-byte nonces, chunked processing, reset, parameter
validation, nonce reuse, and authentication failure.

```bash
cargo test -p tc_gcm --locked
```
