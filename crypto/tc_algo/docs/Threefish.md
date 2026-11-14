# Threefish

Threefish, the block cipher of Skein, takes a tweak besides its key: 16 bytes that change the
cipher without a new key schedule, so a disk sector or a block number can select its own
permutation. Its block and key are the same size, 32, 64 or 128 bytes. The `threefish-256`,
`threefish-512` and `threefish-1024` features have the rows; see
[Block ciphers](BlockCipher.md#threefish-256) for their names.

## A key alone

A `KeyOwned`, or a `KeyWithIvOwned` with an IV, takes a tweak of zeros, as Bouncy Castle gives a
`KeyParameter`.

## A tweak

`ThreefishParamsOwned::with_tweak` sets it. In ECB the params go to the row as they are; in the
modes with an IV they go with the IV in a `ParamsWithIvOwned`, as Bouncy Castle's
`ParametersWithIV(TweakableBlockCipherParameters(key, tweak), iv)`.

```rust
use tc_algo::params::{ParamsWithIvOwned, ThreefishParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "THREEFISH-512/CBC/PKCS7PADDING";

    // A 64-byte key with a 16-byte tweak, and an IV of one block, 64 bytes
    let threefish = ThreefishParamsOwned::with_tweak(key.to_vec(), tweak.to_vec());
    let params = ParamsWithIvOwned::new(threefish, iv.to_vec());

    let ciphertext = algo.cipher().encrypt_by_name(name, &params, message)?;
    Ok(())
}
```

`ThreefishParamsOwned::new(key)` takes a tweak of zeros, as a `KeyOwned` does. The same type serves
the three sizes; only the key, the block and so the IV differ.

| Rows | Params |
|---|---|
| ECB | `KeyOwned` or `ThreefishParamsOwned` |
| CBC, CFB, OFB, CTR | `KeyWithIvOwned` or `ParamsWithIvOwned<ThreefishParamsOwned>` |

The IV is one block in every mode but CTR, which takes it as `tc_block_modes` does. The key and
the tweak are checked when the row is initialized, not when the params are built; a key that is
not one block, or a tweak that is not 16 bytes, is `InvalidParams`.

The rows encrypt in a mode as any block cipher does, and keep one tweak for the whole message. A
scheme that changes the tweak per block, as Skein's UBI does, builds on the engine of
`tc_threefish` instead.
