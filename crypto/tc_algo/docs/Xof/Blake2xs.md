# BLAKE2xs

BLAKE2xs turns BLAKE2s into an XOF: it hashes the message once, then draws output from that hash
in blocks of 32 bytes. It takes the parameters of BLAKE2s: a key, which makes it a MAC, a salt,
and a personalization string, which keeps one use apart from another. [BLAKE2X specification](https://www.blake2.net/blake2x.pdf)

`BLAKE2XS` is behind the `blake` feature.

## Keyed output

```rust
use tc_algo::params::xof::Blake2xsParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let key = vec![0x42; 32]; // Example key

    // The XOF
    let mut xof = algo.xof().get_by_name("BLAKE2XS")?;

    // A key, and an 8-byte personalization string
    let params = Blake2xsParams::new()
        .with_key(key)
        .with_personalization(b"MyApp v1".to_vec());
    xof.init(&params)?;

    // The message
    xof.try_update(b"attack at dawn")?;

    // Request 48 bytes of keyed output
    let output = xof.finalize_len(48)?;
    Ok(())
}
```

## Params

`Blake2xsParams`, is in `tc_algo::params::xof`. Its three settings are optional.

- `with_key(Vec<u8>)`: at most 32 bytes. With a nonempty secret key, the output is a MAC of the message. The key
  is wiped when the params are dropped.
- `with_salt(Vec<u8>)`: exactly 8 bytes.
- `with_personalization(Vec<u8>)`: exactly 8 bytes, chosen by the application.

A value of another length is `InvalidParams` from `init`, as are params of another type.

## Initialization and output length

You can call `try_update` immediately after lookup. The default has no key, salt or
personalization. Calling `init` starts a new message with the supplied settings.
Calling `try_reset` discards the current message and keeps those settings.

The factory selects BLAKE2xs in unknown-length mode. With the same settings and message,
the first 32 bytes returned by `finalize_len(48)` match the result of `finalize_len(32)`.
For interoperability, select unknown-length mode on both sides.

- `finalize_len(n)` returns the requested number of bytes and resets the message.
- `try_output` reads successive chunks from the same message. Keep the total within
  2^32 blocks of 32 bytes (128 GiB).
- `digest_size()` reports 65,535, the unknown-length marker. The digest helper `finalize()`
  therefore returns 65,535 bytes. Use `finalize_len(n)` to choose the size explicitly.
