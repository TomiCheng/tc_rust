# BLAKE3

BLAKE3 is a fast hash with output of any length, and three modes: a plain hash, a keyed hash, and
key derivation. `init` picks the mode with `Blake3Params`, after Bouncy Castle's
`Blake3Parameters`.

`BLAKE3` is behind the `blake3` feature.

## Keyed hash

With a 32-byte key, the output is a MAC of the message.

```rust
use tc_algo::params::Blake3Params;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let key = vec![0x42; 32];

    let mut xof = algo.xof().get_by_name("BLAKE3")?;
    xof.init(&Blake3Params::keyed(key))?;
    xof.try_update(b"attack at dawn")?;
    let tag = xof.finalize_len(32)?;
    Ok(())
}
```

## Key derivation

With a context string, the input is key material and the output a key derived from it. The context
is fixed in the application's source, and names the application and the purpose of the key, so
that two uses never derive the same key.

```rust
use tc_algo::params::Blake3Params;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let shared_secret = [0x17; 32];

    let mut xof = algo.xof().get_by_name("BLAKE3")?;
    let context = b"MyApp 2026-11-12 session encryption key".to_vec();
    xof.init(&Blake3Params::derive_key(context))?;
    xof.try_update(&shared_secret)?;
    let session_key = xof.finalize_len(32)?;
    Ok(())
}
```

## Params

`Blake3Params`, from `tc_algo::params`, one of:

- `keyed(Vec<u8>)`: a key of exactly 32 bytes, for the keyed hash. The key is wiped when the
  params are dropped.
- `derive_key(Vec<u8>)`: a context string of any length, for key derivation.

A key of another length is `InvalidParams` from `init`, as are params of another type.

## Using it

- `init` is optional: without it, BLAKE3 is the plain hash.
- `init` starts a new message, and `try_reset` keeps the mode it set.
- The message may come in any number of updates, and the output be taken in pieces with
  `try_output`; a shorter output is the start of a longer one.
- As a `Digest`, `finalize` gives 32 bytes.
- The context is not a secret and not a salt: it should not hold data that changes from one call to
  the next. Put that in the input.