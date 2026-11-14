# Ascon-CXOF128

Ascon-CXOF128, of NIST SP 800-232, is Ascon-XOF128 with a customization string Z mixed in before
the message. Under two customization strings the same message gives two unrelated outputs, so one
function serves several purposes without one standing in for another. Ascon is light, for small
devices and short messages.

`ASCON-CXOF128` is behind the `ascon-cxof128` feature.

## Hashing with a customization string

```rust
use tc_algo::params::AsconCXofParams;
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

    // 32 bytes of output
    let tag = cxof.finalize_len(32)?;
    Ok(())
}
```

## Params

`AsconCXofParams`, from `tc_algo::params`:

- `new()`: an empty customization string.
- `with_customization(Vec<u8>)`: Z, chosen by the application, at most 256 bytes as SP 800-232
  allows.

A longer Z is `InvalidParams` from `init`, as are params of another type.

## Using it

- `init` is optional: without it, Z is empty. That is still Ascon-CXOF128, not Ascon-XOF128: the two
  give different outputs for the same message.
- `init` starts a new message, and `try_reset` keeps the string it set.
- The message may come in any number of updates, and the output be taken in pieces with
  `try_output`; a shorter output is the start of a longer one.
- As a `Digest`, `finalize` gives 32 bytes.
- Both sides must use the same Z.