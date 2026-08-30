# tc_key_wrap

`tc_key_wrap` provides pure-Rust key-wrapping algorithms for protecting
cryptographic key material with a key-encryption key (KEK). Unlike ordinary
encryption, a key-wrap format also carries an integrity check: unwrap rejects a
wrong KEK or modified wrapped value instead of returning unauthenticated key
bytes.

The crate implements the [`KeyWrap`](../tc_cipher_core/src/key_wrap.rs) and
`KeyWrapInit` traits from `tc_cipher_core`. Initialization is separate from the
caller-buffer wrap and unwrap operations.

> This is a learning port of Bouncy Castle's C# implementations and has not
> received an independent security audit. Do not use it as a replacement for
> an audited cryptographic library.

## Add the crates

When consuming the crates from this workspace, add the wrapper, cipher, and
trait crates:

```toml
[dependencies]
tc_key_wrap = { path = "../tc_key_wrap" }
tc_block_cipher = { path = "../tc_block_cipher" }
tc_cipher_core = { path = "../tc_cipher_core" }
```

Wrappers that generate an IV or random padding are generic over
`rand_core::CryptoRng`; the application chooses and owns the random-number
generator.

## Quick start: AES Key Wrap

This example wraps and unwraps a 128-bit key with RFC 3394 AES Key Wrap:

```rust
use tc_block_cipher::AesParams;
use tc_cipher_core::{KeyWrap, KeyWrapInit, WrapDirection};
use tc_key_wrap::{AesWrapEngine, Rfc3394Params};

let kek = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];
let key = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];

let params = Rfc3394Params::new(AesParams::new(&kek).unwrap());
let mut wrapper = AesWrapEngine::default();

wrapper.init(WrapDirection::Wrap, &params).unwrap();
let mut wrapped = vec![0_u8; wrapper.wrapped_len(key.len()).unwrap()];
let wrapped_len = wrapper.wrap_into(&key, &mut wrapped).unwrap();

wrapper.init(WrapDirection::Unwrap, &params).unwrap();
let mut recovered = vec![0_u8; wrapper.max_unwrapped_len(wrapped_len).unwrap()];
let recovered_len = wrapper
    .unwrap_into(&wrapped[..wrapped_len], &mut recovered)
    .unwrap();

assert_eq!(&recovered[..recovered_len], &key);
```

`wrapped_len()` returns the exact wrap output size. `max_unwrapped_len()`
returns a sufficient output capacity; formats that encode the original length
may write fewer bytes, so always use the length returned by `unwrap_into()`.

`KeyWrap` contains only the initialized operations and is object-safe. An
initialized implementation can therefore be stored as
`dyn KeyWrap<Error = E>`. `KeyWrapInit` remains strongly typed so each
algorithm can accept its own key, IV, and configuration parameters.

## Error handling

Sizing methods reject unsupported input lengths before processing.
`wrap_into()` and `unwrap_into()` also report an uninitialized wrapper, the
wrong operation direction, or an output buffer that is too short. Unwrap does
not release unauthenticated key material when the integrity check fails.

## Implemented algorithms

| Engine | Format | Accepted key material | Randomness |
| --- | --- | --- | --- |
| `Rfc3394WrapEngine<E>` | RFC 3394 | At least 8 bytes; multiple of 8 | None |
| `AesWrapEngine` | RFC 3394 with AES | At least 8 bytes; multiple of 8 | None |
| `AriaWrapEngine` | RFC 3394 with ARIA | At least 8 bytes; multiple of 8 | None |
| `CamelliaWrapEngine` | RFC 3394 with Camellia | At least 8 bytes; multiple of 8 | None |
| `SeedWrapEngine` | RFC 3394 with SEED | At least 8 bytes; multiple of 8 | None |
| `Rfc5649WrapEngine<E>` | RFC 5649 with padding | Non-empty; length encoded as `u32` | None |
| `AesWrapPadEngine` | RFC 5649 with AES | Non-empty; length encoded as `u32` | None |
| `AriaWrapPadEngine` | RFC 5649 with ARIA | Non-empty; length encoded as `u32` | None |
| `Rfc3211WrapEngine<E, R>` | RFC 3211, CBC | 0 to 255 bytes | Random padding; caller supplies IV |
| `DesEdeWrapEngine<R>` | RFC 3217 Triple-DES | Multiple of 8 | Random IV unless explicitly supplied |
| `Rc2WrapEngine<R>` | RFC 3217 RC2 | 0 to 255 bytes | Random IV and padding |
| `Dstu7624WrapEngine<BLOCK_WORDS, KEY_WORDS>` | DSTU 7624 | Multiple of selected block size | None |

The generic RFC 3394 and RFC 5649 engines require an underlying cipher with a
16-byte block. DSTU 7624 supports the valid 128-, 256-, and 512-bit block/key
configurations exposed by `tc_block_cipher`.

The RFC 3217 algorithms retain SHA-1 because their formats define the first
eight SHA-1 output bytes as the checksum. SHA-1 is not used here as a general
collision-resistant hash.

## Random IVs and padding

`Rfc3211WrapEngine`, `DesEdeWrapEngine`, and `Rc2WrapEngine` receive a concrete
`R: CryptoRng` in their constructors. The crate never obtains entropy from a
global source.

`DesEdeWrapParams::new` and `Rc2WrapParams::new` generate the wrapping IV from
that RNG. Their `with_iv` constructors accept an explicit 8-byte IV for test
vectors or protocols that already provide one. Unwrap rejects an externally
supplied IV because the wrapped value already contains it.

Use a fresh, cryptographically secure RNG in normal operation. Reusing fixed
IVs or deterministic padding outside test vectors can invalidate the security
properties expected by these formats. For `DesEdeWrapEngine` and
`Rc2WrapEngine`, initialize again with parameters built by `new` before each
wrap so `init` draws a fresh IV. RFC 3211 callers should likewise supply a
fresh IV for each wrapping operation.

## `no_std` and allocation

The crate is always `no_std`, but it requires `alloc`. Some CBC-based wrappers
and modes keep state or temporary unwrap data in `Vec` buffers. A `no_std`
application must therefore provide an allocator; there is no separate `std`
feature, and using the crate from a `std` application does not change the
available algorithms.

RFC 3394, RFC 5649, and DSTU 7624 process caller-provided output buffers without
heap allocation in their key-wrap paths. Other implementations may allocate
internal scratch storage even though the result itself is written into the
caller's buffer.

## Build and test

From the workspace root:

```text
cargo build -p tc_key_wrap --locked
cargo test -p tc_key_wrap --locked
cargo clippy -p tc_key_wrap --all-targets --locked -- -D warnings
cargo rustdoc -p tc_key_wrap --locked -- -D warnings
```

The normal library build compiles the crate as `no_std + alloc`. Tests use
Rust's standard test harness. For an embedded target, add `--target <triple>`
to the build command and ensure the final application supplies an allocator.
