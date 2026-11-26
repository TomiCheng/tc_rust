# Ascon-CXOF128

Ascon-CXOF128 is a customizable extendable-output function for constrained devices. It absorbs
a customization string Z before the message. An application can use Z to distinguish purposes,
such as hashing a firmware image and hashing a sensor reading. [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final)

`ASCON-CXOF128` is behind the `ascon-hash` feature.

## Hashing with a customization string

```rust
use tc_algo::params::xof::AsconCXofParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The XOF
    let mut cxof = algo.xof().get_by_name("ASCON-CXOF128")?;

    // The customization string
    let params = AsconCXofParams::new().with_customization(b"sensor firmware v3".to_vec());
    cxof.init(&params)?;

    // The message, in any number of updates
    cxof.try_update(b"reading 17.4 C")?;

    // Request 32 bytes. The caller chooses the output length in bytes.
    let output = cxof.finalize_len(32)?;
    Ok(())
}
```

## Params

`AsconCXofParams`, from `tc_algo::params::xof`:

- `new()`: an empty customization string.
- `with_customization(Vec<u8>)`: Z, chosen by the application, at most 256 bytes as SP 800-232
  allows.

A longer Z is `InvalidParams` from `init`, as are params of another type.

## Using it

- You can call `try_update` immediately after lookup. The default Z is empty. Even with empty Z,
  Ascon-CXOF128 uses its own initialization and gives different output from Ascon-XOF128.
- `init` starts a new message, and `try_reset` keeps the string it set.
- The message may come in any number of updates, and the output be taken in pieces with
  `try_output`; a shorter output is the start of a longer one.
- As a `Digest`, `finalize` gives 32 bytes.
- Both sides must use the same Z.