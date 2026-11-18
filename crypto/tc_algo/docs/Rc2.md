# RC2

RC2, of RFC 2268, has an effective key size besides its key: the key is reduced to that many bits
before the key schedule. RSA's PKCS#5 and S/MIME named it with the key, and CMS still carries it
in an RC2-CBC parameter. The `rc-cipher` feature has the rows; see
[Block ciphers](BlockCipher.md#rc2) for their names.

RC2 is weak and legacy: use it only to read data that already uses it.

## A key alone

A `KeyOwned`, or a `KeyWithIvOwned` with an IV, gives an effective key size of the whole key, as
Bouncy Castle gives a `KeyParameter`: a 16-byte key has 128 effective bits.

## Another effective key size

`Rc2ParamsOwned::with_effective_key_bits` sets it. In ECB the params go to the row as they are; in
the modes with an IV they go with the IV in a `ParamsWithIvOwned`, as Bouncy Castle's
`ParametersWithIV(RC2Parameters, iv)`.
In the AEAD modes they go with the nonce, the tag size and the initial AAD in a
`ParamsWithAeadOwned`, which Bouncy Castle has no counterpart of: its `AeadParameters` takes a
`KeyParameter` alone.

In a block cipher mode, CBC here:

```rust
use tc_algo::params::{cipher::ParamsWithIvOwned, key::Rc2ParamsOwned};
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

In an AEAD mode, EAX, the only one of RC2's 8-byte block:

```rust
use tc_algo::params::{cipher::ParamsWithAeadOwned, key::Rc2ParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "RC2/EAX/NOPADDING";

    // A 16-byte key with 40 effective bits, a nonce, a tag of 8 bytes and the AAD
    let rc2 = Rc2ParamsOwned::with_effective_key_bits(key.to_vec(), 40);
    let params = ParamsWithAeadOwned::new(rc2, nonce.to_vec(), 8, aad.to_vec());

    // The tag at the end of the input is checked; a wrong one is InvalidCiphertext
    let plaintext = algo.cipher().decrypt_by_name(name, &params, &sealed)?;
    Ok(())
}
```

`Rc2ParamsOwned::new(key)` gives the whole key's size, as a `KeyOwned` does.

| Rows | Params |
|---|---|
| ECB | `KeyOwned` or `Rc2ParamsOwned` |
| CBC, CFB, OFB, CTR, GOFB, OPENPGPCFB | `KeyWithIvOwned` or `ParamsWithIvOwned<Rc2ParamsOwned>` |
| EAX | `AeadParamsOwned` or `ParamsWithAeadOwned<Rc2ParamsOwned>` |

The IV is one block, 8 bytes, in every mode but CTR, which takes it as `tc_block_modes` does.
The effective key size is checked when the row is initialized, not when the params are built; a
size outside 1 to 1024 bits is `InvalidParams`.

## Key generation

The `RC2` row of `algo.key_generator()` gives an `Rc2ParamsOwned`, the key with what the cipher
takes besides it, which goes straight into the rows above. `init` takes an `Rc2KeyGenParams`; see
[Key generation](KeyGeneration.md).

```rust
use tc_algo::params::{generate::Rc2KeyGenParams, key::Rc2Params, key::Rc2ParamsOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();

    // A 5-byte key of 40 effective bits, as the 40-bit RC2 of old S/MIME and PKCS#12
    let params = Rc2KeyGenParams::new(5);
    let rc2 = algo.key_generator().generate_by_name_with("RC2", &params)?;
    let rc2 = rc2.as_any().downcast_ref::<Rc2ParamsOwned>().expect("an Rc2ParamsOwned");
    assert_eq!(rc2.effective_key_bits(), 40);
    Ok(())
}
```

`Rc2KeyGenParams::new(key_bytes)` sets the length of the key, 1 to 128 bytes, and
`with_effective_key_bits` the effective key size, 1 to 1024 bits; without it, the size is that of
the whole key. Without `init`, the row gives a key of 16 bytes and 128 effective bits. The values
are checked when the row is initialized, not when the params are built; one out of range is
`InvalidParams`.

## The effective key size in CMS

RFC 8018 and RFC 3370 write the size as an RC2 parameter version: 160 for 40 bits, 120 for 64 and
58 for 128, and any number of 256 or more as the size itself. These rows take the size in bits, so
read the version and convert it before building the params.
