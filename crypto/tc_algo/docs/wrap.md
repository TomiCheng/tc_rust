# Key wrap

A key wrapper protects a key under another key, the key-encryption key or KEK, so that it can be
stored or sent. `algo.wrap()` creates wrappers by name or by OID, after Bouncy Castle's
`WrapperUtilities`. Every wrapper it creates is an `AnyWrapper`.

## Enabling wrappers

Nothing is on by default. A wrapper needs the feature of its kind of wrap and that of its cipher, as
the [table](#algorithms) below lists.

```toml
[dependencies]
tc_algo = { version = "0.1", features = ["rfc3394-wrap", "aes"] }
```

## Usage

### Step by step

Get a wrapper, initialize it for one direction, then wrap or unwrap. `unwrap_key` gives a `SecretKey`,
whose bytes are wiped when it is dropped.

```rust
use tc_algo::{Algo, AlgoError, AnyWrapParams, SecretKey, WrapDirection};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let params = AnyWrapParams::new(SecretKey::new(vec![0x42; 32]));

    let mut wrapper = algo.wrap().get_by_name("AESWRAP")?;
    wrapper.init(WrapDirection::Wrap, &params)?;
    let wrapped = wrapper.wrap_key(&[0x24; 32])?;

    wrapper.init(WrapDirection::Unwrap, &params)?;
    let key = wrapper.unwrap_key(&wrapped)?;
    assert_eq!(key.key, [0x24; 32]);
    Ok(())
}
```

### In one step

```rust
use tc_algo::{Algo, AlgoError, AnyWrapParams, SecretKey};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let params = AnyWrapParams::new(SecretKey::new(vec![0x42; 32]));

    let wrapped = algo.wrap().wrap_key("AESWRAPPAD", &params, b"a key of any length")?;
    let key = algo.wrap().unwrap_key("AESWRAPPAD", &params, &wrapped)?;
    assert_eq!(key.key, b"a key of any length");
    Ok(())
}
```

### With an IV

RFC 3211 needs an IV of one block, the same for both directions. The others can do without one.

```rust
use tc_algo::{Algo, AlgoError, AnyWrapParams, SecretKey};

fn main() -> Result<(), AlgoError> {
    let algo = Algo::new();
    let params = AnyWrapParams::new(SecretKey::new(vec![0x42; 32])).with_iv(vec![0x11; 16]);

    let wrapped = algo.wrap().wrap_key("AESRFC3211WRAP", &params, &[0x24; 16])?;
    let key = algo.wrap().unwrap_key("AESRFC3211WRAP", &params, &wrapped)?;
    assert_eq!(key.key, [0x24; 16]);
    Ok(())
}
```

### When it fails

| `ErrorKind` | When |
|---|---|
| `UnknownWrapper` | The name or OID is not in the table, or one of the row's features is off |
| `InvalidParams` | `init` with a KEK or an IV the wrapper does not take; a wrapper used in the other direction than its `init` |
| `NotInitialized` | `wrap_key` or `unwrap_key` before a successful `init` |
| `DataLength` | `wrap_key` with a key of a length the wrapper cannot take |
| `InvalidCiphertext` | `unwrap_key` of a wrapped key that fails its check, or is of the wrong length |

## Algorithms

| Name | Aliases | OID | Features | IV |
|---|---|---|---|---|
| AESWRAP | AESKW | `2.16.840.1.101.3.4.1.5`, `.25`, `.45` | `rfc3394-wrap`, `aes` | optional, 8 bytes |
| ARIAWRAP | ARIAKW | `1.2.410.200046.1.1.40`, `.41`, `.42` | `rfc3394-wrap`, `aria` | optional, 8 bytes |
| CAMELLIAWRAP | | `1.2.392.200011.61.1.1.3.2`, `.3`, `.4` | `rfc3394-wrap`, `camellia` | optional, 8 bytes |
| SEEDWRAP | SEEDKW | `1.2.410.200004.7.1.1.1` | `rfc3394-wrap`, `seed` | optional, 8 bytes |
| AESWRAPPAD | AESKWP, AESRFC5649WRAP | `2.16.840.1.101.3.4.1.8`, `.28`, `.48` | `rfc5649-wrap`, `aes` | optional, 4 bytes |
| ARIAWRAPPAD | ARIAKWP | `1.2.410.200046.1.1.43`, `.44`, `.45` | `rfc5649-wrap`, `aria` | optional, 4 bytes |
| AESRFC3211WRAP | | — | `rfc3211-wrap`, `aes` | required, 16 bytes |
| ARIARFC3211WRAP | | — | `rfc3211-wrap`, `aria` | required, 16 bytes |
| CAMELLIARFC3211WRAP | | — | `rfc3211-wrap`, `camellia` | required, 16 bytes |
| DESRFC3211WRAP | | — | `rfc3211-wrap`, `des` | required, 8 bytes |
| DESEDERFC3211WRAP | | — | `rfc3211-wrap`, `desede` | required, 8 bytes |

Names match without regard to ASCII case, and a dotted OID string works wherever a name does. Every
key length's OID finds the same row, and the row takes any KEK its cipher does: the OID does not tie
the KEK to its length.

## Notes

- **What each can wrap**: RFC 3394 takes a whole number of 8-byte blocks, at least one; RFC 5649
  takes any length, at least 1 byte; RFC 3211 pads with random bytes, so its output differs each
  time.
- **Not here yet**: Bouncy Castle's `DESEDEWRAP` (RFC 3217) and `RC2WRAP`. It also uses any cipher of
  its cipher factory as a wrapper when the name is not one of its own; here a name outside the table
  is `UnknownWrapper`.
