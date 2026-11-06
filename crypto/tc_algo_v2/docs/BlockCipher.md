# Block ciphers

From a new key to the decrypted message, with AES in CBC mode and PKCS#7 padding. The `aes` feature
of `tc_algo_v2` has the rows, and the IV here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo_v2::cipher::KeyWithIvOwned;
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder, KeyOwned, KeyParams};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "AES/CBC/PKCS7PADDING";
    let message = b"attack at dawn";

    // Generate a key
    let key = algo.key_generator().generate_by_name("AES256")?;
    let key = key
        .as_any()
        .downcast_ref::<KeyOwned>()
        .expect("AES256 generates a KeyOwned");

    // Set a new IV
    let mut iv = vec![0; 16];
    UnwrapErr(SysRng).fill_bytes(&mut iv);
    let params = KeyWithIvOwned::new(key.key().to_vec(), iv);

    // Encrypt
    let ciphertext = algo.cipher().encrypt_by_name(name, &params, message)?;

    // Decrypt
    let plaintext = algo.cipher().decrypt_by_name(name, &params, &ciphertext)?;

    assert_eq!(plaintext, message);
    Ok(())
}
```

## Params

Each kind of row takes the type of its mode, and any other type is `InvalidParams`:

| Rows | Params |
|---|---|
| `AES/ECB/*` | `KeyOwned` |
| `AES/CBC/*`, `AES/CFB/*`, `AES/OFB/*` | `KeyWithIvOwned` |

Both come from the crates underneath and wipe themselves when dropped.

## The IV

- Use a new IV for every message under the same key. It is not secret: send it along with the
  ciphertext, since decrypting needs the same one.
- The IV must be 16 bytes, or `init` gives `InvalidParams`. Unlike Bouncy Castle, a short IV is not
  padded with zeros, and there is no default of zeros: `KeyWithIvOwned` always has one to give.
- ECB has no IV. A generated key goes straight into it:

  ```rust
  let ciphertext = algo
      .cipher()
      .encrypt_by_name("AES/ECB/PKCS7PADDING", key.as_ref(), message)?;
  ```

## Keys

- `AES128`, `AES192` and `AES256` generate keys of 16, 24 and 32 bytes. The NIST OID of a mode finds
  the generator of its key length too, as `id-aes256-CBC` does for `AES256`.
- A generated key is a `KeyOwned`, so adding an IV takes a downcast and a new `KeyWithIvOwned`, as
  above. Both hold a copy of the key.

## Authentication

CBC does not detect a changed ciphertext, and the padding check can reveal the plaintext to whoever
can see it fail. Authenticate the ciphertext before decrypting it, or use an AEAD mode.
