# Key wrap

A key wrap encrypts one key under another, the key-encryption key or KEK, so that the first can be
stored or sent. Both sides hold the same KEK, and unwrapping detects a change to the wrapped key or
a wrong KEK. Encrypting a key with someone's public key, such as RSA-OAEP, is a cipher instead.

From a new KEK to the key back again, with AESWRAP. The `aes-wrap` feature of `tc_algo` has the
rows.

```rust
use tc_algo::wrap::WrapDirection;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let key = [0x11; 16];

    // Generate the KEK
    let kek = algo.key_generator().generate_by_name("AES256")?;

    let mut wrapper = algo.wrap().get_by_name("AESWRAP")?;

    // Wrap
    wrapper.init(WrapDirection::Wrap, kek.as_ref())?;
    let wrapped = wrapper.wrap(&key)?;

    // Unwrap
    wrapper.init(WrapDirection::Unwrap, kek.as_ref())?;
    let unwrapped = wrapper.unwrap(&wrapped)?;

    assert_eq!(unwrapped, key);
    Ok(())
}
```

The same with helpers:

```rust
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "AESWRAP";
    let key = [0x11; 16];

    let kek = algo.key_generator().generate_by_name("AES256")?;
    let kek = kek.as_ref();

    let wrapped = algo.wrap().wrap_by_name(name, kek, &key)?;
    let unwrapped = algo.wrap().unwrap_by_name(name, kek, &wrapped)?;

    assert_eq!(unwrapped, key);
    Ok(())
}
```

## Algorithms

| Name | OIDs | Feature | Key to wrap | Added bytes |
|---|---|---|---|---|
| `AESWRAP` | `id-aes128-wrap`, `id-aes192-wrap`, `id-aes256-wrap` | `aes-wrap` | At least 8 bytes, in multiples of 8 | 8 |

`AESKW` finds it too, and the case of a name does not matter. The OIDs are
`2.16.840.1.101.3.4.1.5`, `.25` and `.45` of the same arc. Each says a length of KEK, but the row
takes any AES key under any of them.

## Params

AESWRAP takes a `KeyOwned` of 16, 24 or 32 bytes, and any other type or length is `InvalidParams`. A
key from a key generator goes straight in, and a key from elsewhere with `KeyOwned::new(bytes)`. It
keeps to the IV of the standard: a custom IV is not supported yet.

## Using it

- `init` gives the direction, and the wrapper then works only that way. The other call gives
  `NotInitialized`, as both do before an `init` that succeeded.
- `unwrap` gives `InvalidCiphertext` for a changed input or a wrong KEK, and no output.
- A key of the wrong length gives `DataLength`.
- `unwrap` returns the key in a plain `Vec<u8>`, which does not wipe itself. Wipe it when done.
