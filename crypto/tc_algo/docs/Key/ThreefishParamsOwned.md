# ThreefishParamsOwned

Enable the `threefish` feature to use `ThreefishParamsOwned`. Import it and the
`ThreefishParams` trait from `tc_algo::params::key`. It holds a Threefish key and an
optional 16-byte tweak.

| Method | Setting | Valid length |
|---|---|---|
| `new(key)` | Uses the default all-zero tweak | Key of 32, 64, or 128 bytes |
| `with_tweak(key, tweak)` | Sets an explicit tweak | Key of 32, 64, or 128 bytes, tweak of 16 bytes |

With `new(key)`, the cipher uses an all-zero tweak, the same as a `KeyOwned`. Construction
validates nothing: the cipher checks that the key matches its block size (32 bytes for
`THREEFISH-256`, 64 for `THREEFISH-512`, 128 for `THREEFISH-1024`) and that any explicit
tweak is 16 bytes when it is initialized, returning `InvalidParams` otherwise.

| Accessor | Returns |
|---|---|
| `KeyParams::key()` | The key bytes |
| `ThreefishParams::tweak()` | `Option<&[u8]>` (`None` for the default tweak) |

Both the key and the tweak are wiped when the value is dropped, and `Debug` prints their
lengths, never their bytes.

## Use it with a cipher

| Rows | Params |
|---|---|
| ECB | `ThreefishParamsOwned` |
| CBC, CFB, OFB, CTR, OPENPGPCFB | `ParamsWithIvOwned<ThreefishParamsOwned>` |
| KCCM (`THREEFISH-256` and `THREEFISH-512`) | `ParamsWithAeadOwned<ThreefishParamsOwned>` |

In the modes with an IV the params go with the IV, as Bouncy Castle's
`ParametersWithIV(TweakableBlockCipherParameters(key, tweak), iv)`. In KCCM they go with the nonce,
the tag size and the initial AAD in a `ParamsWithAeadOwned`, which Bouncy Castle has no counterpart
of: its `AeadParameters` takes a `KeyParameter` alone. Threefish-1024 has no AEAD mode.

The rows encrypt in a mode as any block cipher does, and keep one tweak for the whole message. A
scheme that changes the tweak per block, as Skein's UBI does, builds on the engine of
`tc_threefish` instead.

```rust
use tc_algo::params::cipher::ParamsWithIvOwned;
use tc_algo::params::key::ThreefishParamsOwned;
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 64-byte key with a 16-byte tweak, and a 64-byte IV for Threefish-512
    let threefish = ThreefishParamsOwned::with_tweak(vec![0x42; 64], vec![0x11; 16]);
    let params = ParamsWithIvOwned::new(threefish, vec![0; 64]);
    let name = "THREEFISH-512/CBC/PKCS7PADDING";
    let _ciphertext = algo.cipher().encrypt_by_name(name, &params, b"attack at dawn")?;
    Ok(())
}
```

The Threefish key generators return a `ThreefishParamsOwned`; see
[`ThreefishKeyGenParams`](../KeyGeneration/ThreefishKeyGenParams.md).
[Key generation](../KeyGeneration.md) · [Threefish](../BlockCipher/Threefish-256.md)
