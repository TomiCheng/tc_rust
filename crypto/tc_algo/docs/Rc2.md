# RC2

RC2, of RFC 2268, has an effective key size besides its key: the key is reduced to that many bits
before the key schedule. RSA's PKCS#5 and S/MIME named it with the key, and CMS still carries it
in an RC2-CBC parameter. The `rc2` feature has the rows; see
[Block ciphers](BlockCipher.md#rc2) for their names.

RC2 is weak and legacy: use it only to read data that already uses it.

## A key alone

A `KeyOwned`, or a `KeyWithIvOwned` with an IV, gives an effective key size of the whole key, as
Bouncy Castle gives a `KeyParameter`: a 16-byte key has 128 effective bits.

## Another effective key size

`Rc2ParamsOwned::with_effective_key_bits` sets it. In ECB the params go to the row as they are; in
the modes with an IV they go with the IV in a `ParamsWithIvOwned`, as Bouncy Castle's
`ParametersWithIV(RC2Parameters, iv)`.

```rust
use tc_algo::params::{ParamsWithIvOwned, Rc2ParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RC2/CBC/PKCS7PADDING";

    // A 16-byte key with 40 effective bits, and an IV of one block, 8 bytes
    let rc2 = Rc2ParamsOwned::with_effective_key_bits(key.to_vec(), 40);
    let params = ParamsWithIvOwned::new(rc2, iv.to_vec());

    let plaintext = algo.cipher().decrypt_by_name(name, &params, &ciphertext)?;
    Ok(())
}
```

`Rc2ParamsOwned::new(key)` gives the whole key's size, as a `KeyOwned` does.

| Rows | Params |
|---|---|
| ECB | `KeyOwned` or `Rc2ParamsOwned` |
| CBC, CFB, OFB, CTR | `KeyWithIvOwned` or `ParamsWithIvOwned<Rc2ParamsOwned>` |

The IV is one block, 8 bytes, in every mode but CTR, which takes it as `tc_block_modes` does.
The effective key size is checked when the row is initialized, not when the params are built; a
size outside 1 to 1024 bits is `InvalidParams`.

## The effective key size in CMS

RFC 8018 and RFC 3370 write the size as an RC2 parameter version: 160 for 40 bits, 120 for 64 and
58 for 128, and any number of 256 or more as the size itself. These rows take the size in bits, so
read the version and convert it before building the params.
