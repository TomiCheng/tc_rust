# BLAKE3

The factory returns a BLAKE3 hasher in plain hash mode. You can call `try_update` immediately.
To authenticate a message or derive a key, select the corresponding mode with `init` and
`Blake3Params`. All three modes support extendable output. [BLAKE3 project](https://github.com/BLAKE3-team/BLAKE3)

`BLAKE3` is behind the `blake` feature.

## Keyed hash

With a 32-byte key, the output is a MAC of the message.

```rust
use tc_algo::params::xof::Blake3Params;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let key = vec![0x42; 32]; // Example key

    let mut xof = algo.xof().get_by_name("BLAKE3")?;
    xof.init(&Blake3Params::keyed(key))?;
    xof.try_update(b"attack at dawn")?;
    let tag = xof.finalize_len(32)?;
    Ok(())
}
```

## Key derivation

With a context string, the input is key material and the output a key derived from it. Use a fixed, public context string that names the application and the purpose of the derived key.

```rust
use tc_algo::params::xof::Blake3Params;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let shared_secret = [0x17; 32]; // Example key material

    let mut xof = algo.xof().get_by_name("BLAKE3")?;
    let context = b"MyApp 2026-11-12 session encryption key".to_vec();
    xof.init(&Blake3Params::derive_key(context))?;
    xof.try_update(&shared_secret)?;
    let session_key = xof.finalize_len(32)?;
    Ok(())
}
```

## Params

`Blake3Params`, is in `tc_algo::params::xof`. Choose one of its two constructors.

- `keyed(Vec<u8>)`: a key of exactly 32 bytes, for the keyed hash. The key is wiped when the
  params are dropped.
- `derive_key(Vec<u8>)`: a context string of any length, for key derivation.

A key of another length is `InvalidParams` from `init`, as are params of another type.

## Output and reset

`finalize()` returns 32 bytes. Use `finalize_len(n)` to request a length in bytes.
For the same mode, parameters and message, a 32-byte result is the prefix of a 64-byte result.

Use `try_output` to read successive chunks. After reading a chunk, `finalize_len(n)` returns
the next `n` bytes and resets the message. Both finalization and `try_reset` preserve the
selected mode and its parameters.
