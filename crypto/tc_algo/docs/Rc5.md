# RC5

RC5, of Rivest's paper and RFC 2040, takes a number of rounds besides its key. `RC5` (also
`RC5-32`) has 32-bit words and an 8-byte block, and `RC5-64` 64-bit words and a 16-byte block,
both behind the `rc-cipher` feature. See [Block ciphers](BlockCipher.md#rc5) for their
names.

RC5 is legacy: use it only to read data that already uses it.

## A key alone

A `KeyOwned`, or a `KeyWithIvOwned` with an IV, gives 12 rounds, as Bouncy Castle gives a
`KeyParameter`.

## Another number of rounds

`Rc5ParamsOwned::new(key, rounds)` sets it. In ECB the params go to the row as they are; in the
modes with an IV they go with the IV in a `ParamsWithIvOwned`, as Bouncy Castle's
`ParametersWithIV(RC5Parameters, iv)`.
In the AEAD modes they go with the nonce, the tag size and the initial AAD in a
`ParamsWithAeadOwned`, which Bouncy Castle has no counterpart of: its `AeadParameters` takes a
`KeyParameter` alone.

In a block cipher mode, CBC here:

```rust
use tc_algo::params::{cipher::ParamsWithIvOwned, key::Rc5ParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RC5/CBC/PKCS7PADDING";

    // A 16-byte key with 16 rounds, and an IV of one block, 8 bytes
    let rc5 = Rc5ParamsOwned::new(key.to_vec(), 16);
    let params = ParamsWithIvOwned::new(rc5, iv.to_vec());

    let ciphertext = algo.cipher().encrypt_by_name(name, &params, message)?;
    Ok(())
}
```

In an AEAD mode, GCM here, of RC5-64 and its 16-byte block; `RC5`, of an 8-byte block, has EAX
alone:

```rust
use tc_algo::params::{cipher::ParamsWithAeadOwned, key::Rc5ParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RC5-64/GCM/NOPADDING";

    // A 16-byte key with 16 rounds, a 12-byte nonce, a tag of 16 bytes and the AAD
    let rc5 = Rc5ParamsOwned::new(key.to_vec(), 16);
    let params = ParamsWithAeadOwned::new(rc5, nonce.to_vec(), 16, aad.to_vec());

    // The tag ends the output
    let sealed = algo.cipher().encrypt_by_name(name, &params, message)?;
    Ok(())
}
```

The same `Rc5ParamsOwned` serves `RC5` and `RC5-64`; only the block, and so the IV, differ, and only
`RC5`, of a block of 8 bytes, has GOFB.

| Rows | Params |
|---|---|
| ECB | `KeyOwned` or `Rc5ParamsOwned` |
| CBC, CFB, OFB, CTR, GOFB, OPENPGPCFB | `KeyWithIvOwned` or `ParamsWithIvOwned<Rc5ParamsOwned>` |
| EAX; for RC5-64 also GCM, CCM, OCB, KCCM | `AeadParamsOwned` or `ParamsWithAeadOwned<Rc5ParamsOwned>` |
| GCM-SIV of RC5-64 | `AeadParamsOwned` |

The IV is one block in every mode but CTR, which takes it as `tc_block_modes` does. The number of
rounds is checked when the row is initialized, not when the params are built; one the engine does
not take is `InvalidParams`.

## Key generation

The `RC5` row of `algo.key_generator()` gives an `Rc5ParamsOwned`, the key with what the cipher
takes besides it, which goes straight into the rows above. `init` takes an `Rc5KeyGenParams`; see
[Key generation](KeyGeneration.md).

```rust
use tc_algo::params::{generate::Rc5KeyGenParams, key::Rc5Params, key::Rc5ParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 16-byte key with 16 rounds
    let params = Rc5KeyGenParams::new(16).with_rounds(16);
    let rc5 = algo.key_generator().generate_by_name_with("RC5", &params)?;
    let rc5 = rc5.as_any().downcast_ref::<Rc5ParamsOwned>().expect("an Rc5ParamsOwned");
    assert_eq!(rc5.rounds(), 16);
    Ok(())
}
```

`Rc5KeyGenParams::new(key_bytes)` sets the length of the key, 1 to 255 bytes, and `with_rounds` the
number of rounds, 0 to 255; without it, 12. Without `init`, `RC5` gives a key of 16 bytes and
`RC5-64` one of 32, each with 12 rounds. The values are checked when the row is initialized, not
when the params are built; one out of range is `InvalidParams`.
