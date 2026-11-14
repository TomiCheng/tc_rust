# cSHAKE

cSHAKE, of NIST SP 800-185, is SHAKE with two strings mixed in before the message: a function
name N and a customization string S. The same message under two customization strings gives two
unrelated outputs, so one hash function serves several purposes without one standing in for
another. With both strings empty it is SHAKE itself.

`CSHAKE128` and `CSHAKE256` are behind the `cshake128` and `cshake256` features.

## Hashing with a customization string

```rust
use tc_algo::params::CShakeParams;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // The XOF
    let mut cshake = algo.xof().get_by_name("CSHAKE128")?;

    // Set the customization string; leave the function name empty
    let params = CShakeParams::new().with_customization(b"MyApp session id v1".to_vec());
    cshake.init(&params)?;

    // The message, in any number of updates
    cshake.try_update(b"user 42, ")?;
    cshake.try_update(b"2026-11-12")?;

    // 32 bytes of output
    let id = cshake.finalize_len(32)?;

    // The same at once
    let message = b"user 42, 2026-11-12";
    let again = algo.xof().calculate_by_name_with("CSHAKE128", &params, message, 32)?;
    assert_eq!(id, again);
    Ok(())
}
```

## Params

`CShakeParams`, from `tc_algo::params`:

- `new()`: both strings empty.
- `with_customization(Vec<u8>)`: S, chosen by the application, such as its name and the purpose
  of the hash.
- `with_function_name(Vec<u8>)`: N, which SP 800-185 reserves for functions NIST defines on
  cSHAKE, such as `"KMAC"` and `"TupleHash"`. An application leaves it empty.

Neither string has a limit, and `init` takes any. Params of another type are `InvalidParams`.

## Using it

- `init` is optional: without it, cSHAKE runs with both strings empty, and its output is that of
  SHAKE128 or SHAKE256.
- `init` starts a new message, and `try_reset` keeps the strings it set. A new `init` replaces them.
- The message may come in any number of updates: `update(b"ab")` then `update(b"c")` is the same
  as `update(b"abc")`.
- The output may be taken in pieces with `try_output`, and a shorter output is the start of a longer
  one, as with SHAKE. `finalize_len` and `try_output_final` end the message.
- As a `Digest`, `finalize` gives 32 bytes for `CSHAKE128` and 64 for `CSHAKE256`.
- Both sides must use the same strings: an output under one S is not the output under another,
  nor under none.
