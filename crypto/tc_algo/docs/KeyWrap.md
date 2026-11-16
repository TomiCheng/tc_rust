# Key wrap

A key wrap encrypts one key under another, the key-encryption key or KEK, so that the first can be
stored or sent. Both sides hold the same KEK, and unwrapping detects a change to the wrapped key or
a wrong KEK. Encrypting a key with someone's public key, such as RSA-OAEP, is a cipher instead.

From a new KEK to the key back again, with AESWRAP. The `rfc3394-wrap` and `aes` features of
`tc_algo` have the row.

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

The names and OIDs are those of Bouncy Castle's `WrapperUtilities`, and the case of a name does not
matter. Each row needs the feature of its wrap and of its cipher. Lengths use `x, y` for those
lengths, `x..y` for a range, and `..` for any length.

| Name | Aliases | OIDs | Features | Params | Key to wrap | Added bytes |
|---|---|---|---|---|---|---|
| `AESWRAP` | `AESKW` | `2.16.840.1.101.3.4.1.5`, `2.16.840.1.101.3.4.1.25`, `2.16.840.1.101.3.4.1.45` | `rfc3394-wrap` and `aes` | `KeyOwned`, `KeyWithIvOwned` | `8..`, in multiples of 8 | 8 |
| `ARIAWRAP` | `ARIAKW` | `1.2.410.200046.1.1.40`, `1.2.410.200046.1.1.41`, `1.2.410.200046.1.1.42` | `rfc3394-wrap` and `aria` | `KeyOwned`, `KeyWithIvOwned` | `8..`, in multiples of 8 | 8 |
| `CAMELLIAWRAP` |  | `1.2.392.200011.61.1.1.3.2`, `1.2.392.200011.61.1.1.3.3`, `1.2.392.200011.61.1.1.3.4` | `rfc3394-wrap` and `camellia` | `KeyOwned`, `KeyWithIvOwned` | `8..`, in multiples of 8 | 8 |
| `SEEDWRAP` | `SEEDKW` | `1.2.410.200004.7.1.1.1` | `rfc3394-wrap` and `seed` | `KeyOwned`, `KeyWithIvOwned` | `8..`, in multiples of 8 | 8 |
| `AESWRAPPAD` | `AESKWP`, `AESRFC5649WRAP` | `2.16.840.1.101.3.4.1.8`, `2.16.840.1.101.3.4.1.28`, `2.16.840.1.101.3.4.1.48` | `rfc5649-wrap` and `aes` | `KeyOwned`, `KeyWithIvOwned` | `1..` | `8..15` |
| `ARIAWRAPPAD` | `ARIAKWP` | `1.2.410.200046.1.1.43`, `1.2.410.200046.1.1.44`, `1.2.410.200046.1.1.45` | `rfc5649-wrap` and `aria` | `KeyOwned`, `KeyWithIvOwned` | `1..` | `8..15` |
| `AESRFC3211WRAP` |  |  | `rfc3211-wrap` and `aes` | `KeyWithIvOwned` | `..255` | to two blocks or more |
| `ARIARFC3211WRAP` |  |  | `rfc3211-wrap` and `aria` | `KeyWithIvOwned` | `..255` | to two blocks or more |
| `CAMELLIARFC3211WRAP` |  |  | `rfc3211-wrap` and `camellia` | `KeyWithIvOwned` | `..255` | to two blocks or more |
| `DESRFC3211WRAP` |  |  | `rfc3211-wrap` and `des` | `KeyWithIvOwned` | `..255` | to two blocks or more |
| `DESEDERFC3211WRAP` |  |  | `rfc3211-wrap` and `desede` | `KeyWithIvOwned` | `..255` | to two blocks or more |

The `WRAP` rows are RFC 3394, which SEED's RFC 4010 and Camellia's RFC 3657 follow, and the
`WRAPPAD` rows RFC 5649, which pads a key of any length. Each OID says a length of KEK, but its row
takes any key of the cipher under any of them. The `RFC3211WRAP` rows are the wrap of CMS's
password-based recipients, RFC 3211: a length byte, a check and random padding, encrypted twice in
CBC, so the same key wraps to a new output each time.

Bouncy Castle's `DESEDEWRAP` and `RC2WRAP`, RFC 3217, are not here yet, nor its fallback to any
cipher name.

## Params

Any other type of params is `InvalidParams`, and so is a KEK of a length the cipher does not take.

- RFC 3394 and RFC 5649 take a `KeyOwned` with the IV of the standard, or a `KeyWithIvOwned` with an
  IV of their own: 8 bytes for RFC 3394, and the 4-byte prefix for RFC 5649.
- RFC 3211 takes a `KeyWithIvOwned` with an IV of a block, for unwrapping as for wrapping. CMS
  carries it in the algorithm identifier, so the IV is not secret, but it must be new for each wrap.

A key from a key generator goes straight in as a `KeyOwned`, and a key from elsewhere with
`KeyOwned::new(bytes)`. Every params type wipes the key when dropped.

## Using it

- `get_by_name` and `get_by_oid` give a `Wrapper`, which is a `KeyWrap` and a `KeyWrapInit` of
  `tc_key_wrap` with `AlgoError` for its errors, so code written for those traits takes it as it
  is.
- `init` gives the direction, and the wrapper then works only that way. The other call gives
  `NotInitialized`, as both do before an `init` that succeeded.
- `unwrap` gives `InvalidCiphertext` for a changed input or a wrong KEK, and no output.
- A key of the wrong length gives `DataLength`.
- `unwrap` returns the key in a plain `Vec<u8>`, which does not wipe itself. Wipe it when done.
