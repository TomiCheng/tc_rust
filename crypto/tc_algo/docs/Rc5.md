# RC5

RC5, of Rivest's paper and RFC 2040, takes a number of rounds besides its key. `RC5` (also
`RC5-32`) has 32-bit words and an 8-byte block, behind the `rc5` feature; `RC5-64` has 64-bit words
and a 16-byte block, behind the `rc5-64` feature. See [Block ciphers](BlockCipher.md#rc5) for their
names.

RC5 is legacy: use it only to read data that already uses it.

## A key alone

A `KeyOwned`, or a `KeyWithIvOwned` with an IV, gives 12 rounds, as Bouncy Castle gives a
`KeyParameter`.

## Another number of rounds

`Rc5ParamsOwned::new(key, rounds)` sets it. In ECB the params go to the row as they are; in the
modes with an IV they go with the IV in a `ParamsWithIvOwned`, as Bouncy Castle's
`ParametersWithIV(RC5Parameters, iv)`.

```rust
use tc_algo::params::{ParamsWithIvOwned, Rc5ParamsOwned};
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

The same `Rc5ParamsOwned` serves `RC5` and `RC5-64`; only the block, and so the IV, differ, and only
`RC5`, of a block of 8 bytes, has GOFB.

| Rows | Params |
|---|---|
| ECB | `KeyOwned` or `Rc5ParamsOwned` |
| CBC, CFB, OFB, CTR, GOFB | `KeyWithIvOwned` or `ParamsWithIvOwned<Rc5ParamsOwned>` |

The IV is one block in every mode but CTR, which takes it as `tc_block_modes` does. The number of
rounds is checked when the row is initialized, not when the params are built; one the engine does
not take is `InvalidParams`.
