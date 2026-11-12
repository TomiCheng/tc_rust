# MACs

A MAC turns a message and a secret key into a short tag. Whoever has the same key can check the tag,
which shows that the message was not changed and that it came from someone with the key. Unlike a
digest it needs a key, and unlike a signature both sides hold the same one.

From a new key to a verified tag, with HMAC-SHA256. The `hmac-sha256` feature of `tc_algo` has
the rows.

```rust
use tc_algo::params::KeyLength;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "HMAC-SHA256";
    let message = b"attack at dawn";

    // Generate a key
    let key = algo
        .key_generator()
        .generate_by_name_with("KEY", &KeyLength::new(32))?;

    // Calculate the tag
    let mut mac = algo.mac().get_by_name(name)?;
    mac.init(key.as_ref())?;
    mac.update(message)?;
    let tag = mac.finalize()?;

    // Verify the tag
    mac.update(message)?;
    assert!(mac.verify(&tag)?);

    Ok(())
}
```

The same with helpers, when the whole message is at hand:

```rust
use tc_algo::params::KeyLength;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "HMAC-SHA256";
    let message = b"attack at dawn";

    let key = algo
        .key_generator()
        .generate_by_name_with("KEY", &KeyLength::new(32))?;
    let key = key.as_ref();

    let tag = algo.mac().calculate_by_name(name, key, message)?;
    assert!(algo.mac().verify_by_name(name, key, message, &tag)?);

    Ok(())
}
```

## Algorithms

| Name | OID | Feature | Tag bytes | IV bytes |
|---|---|---|---|---|
| `HMAC-SHA256` | `1.2.840.113549.2.9` | `hmac-sha256` | 32 | none |

`HMACSHA256`, `HMAC/SHA256`, `HMAC-SHA-256`, `HMAC/SHA-256` and `HMACSHA-256` find it too, and the
case of a name does not matter.

## Params

HMAC-SHA256 takes a `KeyOwned`, and any other type is `InvalidParams`. It takes a key of any length,
but one shorter than the 32 bytes of the tag weakens it. `KeyOwned` wipes the key when dropped.

The `KEY` key generator gives a `KeyOwned` of the length in a `KeyLength`, so it needs the helper with
params, `generate_by_name_with`. A key from elsewhere goes in with `KeyOwned::new(bytes)`.

## Using it

- Check a tag with `verify`, or `verify_by_name` and `verify_by_oid`, never with `==`. They compare
  in constant time, whereas `==` stops at the first difference and tells an attacker how much of a
  forged tag is right.
- All of them give `Ok(false)` for a wrong tag, not an error, so look at the answer: a bare `?` on
  the call lets a forged message through.
- A message can come in pieces, over several calls of `update`.
- `finalize` and `verify` start the next message under the same key. `reset` discards the message so
  far and keeps the key.
- `update`, `finalize` and `verify` give `NotInitialized` before an `init` that succeeded.
