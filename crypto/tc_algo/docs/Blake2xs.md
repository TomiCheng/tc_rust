# BLAKE2xs

BLAKE2xs turns BLAKE2s into an XOF: it hashes the message once, then draws output from that hash
in blocks of 32 bytes. It takes the parameters of BLAKE2s: a key, which makes it a MAC, a salt,
and a personalization string, which keeps one use apart from another.

`BLAKE2XS` is behind the `blake2xs` feature.

## Keyed output

```rust
use tc_algo::params::Blake2xsParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let key = vec![0x42; 32];

    // The XOF
    let mut xof = algo.xof().get_by_name("BLAKE2XS")?;

    // A key, and an 8-byte personalization string
    let params = Blake2xsParams::new()
        .with_key(key)
        .with_personalization(b"MyApp v1".to_vec());
    xof.init(&params)?;

    // The message
    xof.try_update(b"attack at dawn")?;

    // 48 bytes of keyed output
    let output = xof.finalize_len(48)?;
    Ok(())
}
```

## Params

`Blake2xsParams`, from `tc_algo::params`; each is optional:

- `with_key(Vec<u8>)`: at most 32 bytes. With a key, the output is a MAC of the message. The key
  is wiped when the params are dropped.
- `with_salt(Vec<u8>)`: exactly 8 bytes.
- `with_personalization(Vec<u8>)`: exactly 8 bytes, chosen by the application.

A value of another length is `InvalidParams` from `init`, as are params of another type.

## Using it

- `init` is optional: without it, there is no key, salt or personalization.
- `init` starts a new message, and `try_reset` keeps what it set.
- The output length is not set in advance, so a shorter output is the start of a longer one. It
  can reach 2^32 blocks of 32 bytes, and asking for more panics.
- As a `Digest`, `digest_size` is 65535 and `finalize` gives that many bytes, the marker of an
  unknown length. Take the output with `finalize_len` or `try_output` instead.
- For a MAC of a set length, the `mac` factory is the usual place; BLAKE2xs with a key is for
  output of any length.
