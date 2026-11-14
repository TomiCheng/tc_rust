# TupleHash

TupleHash, of NIST SP 800-185, hashes a list of byte strings, not one message. Each string is
taken with its length, so the list is read back without ambiguity: `("ab", "c")` and `("a", "bc")`
hash differently, where a plain hash of their concatenation would not. It suits a record of
fields, such as a user name, a date and a key ID, hashed or signed as a whole.

`TUPLEHASH128` and `TUPLEHASH256` are behind the `tuplehash128` and `tuplehash256` features.

## Hashing a tuple

Each `try_update` is one element of the tuple.

```rust
use tc_algo::params::TupleHashParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The XOF
    let mut tuple_hash = algo.xof().get_by_name("TUPLEHASH256")?;

    // An optional customization string
    let params = TupleHashParams::new().with_customization(b"MyApp record v1".to_vec());
    tuple_hash.init(&params)?;

    // Three elements, one update each
    tuple_hash.try_update(b"alice")?;
    tuple_hash.try_update(b"2026-11-12")?;
    tuple_hash.try_update(b"key-7")?;

    // 64 bytes of TupleHash
    let hash = tuple_hash.finalize_len(64)?;
    Ok(())
}
```

An element is never split over two updates: to hash a field that arrives in pieces, join the
pieces first. The one-call helper `calculate_by_name_with` passes its whole input as one update,
so it hashes a tuple of one element.

## Fixed length or extendable

SP 800-185 defines two functions, and the length asked for is part of the first:

- **TupleHash**, of a length set in advance: `finalize_len(n)`, `try_output_final` and `finalize` as
  a `Digest`. The length is hashed in, so 32 bytes are not the start of 64 bytes.
- **TupleHashXOF**, of any length: `try_output`, called as many times as needed. A shorter output is
  the start of a longer one.

Both sides must use the same one: the first `try_output` call chooses TupleHashXOF for the rest of
the message, and anything else chooses TupleHash.

```rust
// TupleHashXOF: 100 bytes, read in two pieces
tuple_hash.try_update(b"alice")?;
tuple_hash.try_update(b"key-7")?;
let mut first = [0; 40];
let mut rest = [0; 60];
tuple_hash.try_output(&mut first)?;
tuple_hash.try_output(&mut rest)?;
tuple_hash.try_reset()?;
```

## Params

`TupleHashParams`, from `tc_algo::params`:

- `new()`: an empty customization string.
- `with_customization(Vec<u8>)`: S, chosen by the application, such as its name and the format
  of the record.

The string has no limit, and `init` takes any. Params of another type are `InvalidParams`.

## Using it

- `init` is optional: without it, the customization string is empty.
- `init` starts a new message, and `try_reset` keeps the string it set.
- An empty element is an element too: `update(b"")` changes the hash.
- `try_update_byte` is an element of one byte, so a field fed byte by byte becomes as many elements.
- As a `Digest`, `finalize` gives TupleHash of 32 bytes for `TUPLEHASH128` and 64 for
  `TUPLEHASH256`.
