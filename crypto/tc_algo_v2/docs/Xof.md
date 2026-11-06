# XOFs

An extendable-output function hashes a message into as many bytes as you ask for, where a digest
gives a fixed size. The length is not set in advance: it is given when the output is taken, and the
shorter of two outputs is the start of the longer.

With SHAKE256. The `shake256` feature of `tc_algo_v2` has the row.

```rust
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let message = b"attack at dawn";

    let mut xof = algo.xof().get_by_name("SHAKE256")?;
    xof.update(message)?;

    // Take the output in pieces
    let mut first = [0; 32];
    xof.output(&mut first)?;
    let rest = xof.finalize(32)?;

    // The same with a helper
    let output = algo.xof().calculate_by_name("SHAKE256", message, 64)?;

    assert_eq!([&first[..], &rest[..]].concat(), output);
    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Params |
|---|---|---|---|
| `SHAKE256` | `2.16.840.1.101.3.4.2.12` | `shake256` | none |

`SHAKE-256` finds it too, and the case of a name does not matter.

## Params

`init` is optional, for an XOF with something to set, such as the custom strings of cSHAKE. One with
nothing to set, as SHAKE256 has, refuses any params with `InvalidParams`. The helpers ending in
`_with` call `init` first, and the others do not call it.

## Using it

- `update` gives `XofOutputStarted` once output has begun, since the input is then closed.
- `output` can be called again for the next bytes.
- `finalize` gives the next bytes and starts the next message. `reset` discards the message so far.
