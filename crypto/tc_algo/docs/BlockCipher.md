# Block ciphers

From a new key to the decrypted message, with AES in CBC mode and PKCS#7 padding. The `aes` feature
of `tc_algo` has the rows, and the IV here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{KeyOwned, KeyParams, KeyWithIvOwned};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

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

## Algorithms

| Name | Aliases | OIDs | Feature | Params |
|---|---|---|---|---|
| `AES/ECB/NOPADDING` |  |  | `aes` | `KeyOwned` |
| `AES/ECB/PKCS7PADDING` | `AES/ECB/PKCS7`, `AES/ECB/PKCS5PADDING`, `AES/ECB/PKCS5` | `2.16.840.1.101.3.4.1.1`, `.21`, `.41` | `aes` | `KeyOwned` |
| `AES/CBC/NOPADDING` |  |  | `aes` | `KeyWithIvOwned` |
| `AES/CBC/PKCS7PADDING` | `AES/CBC/PKCS7`, `AES/CBC/PKCS5PADDING`, `AES/CBC/PKCS5` | `2.16.840.1.101.3.4.1.2`, `.22`, `.42` | `aes` | `KeyWithIvOwned` |
| `AES/CFB/NOPADDING` |  | `2.16.840.1.101.3.4.1.4`, `.24`, `.44` | `aes` | `KeyWithIvOwned` |
| `AES/OFB/NOPADDING` |  | `2.16.840.1.101.3.4.1.3`, `.23`, `.43` | `aes` | `KeyWithIvOwned` |

A name is `ALGORITHM/MODE/PADDING`, after Bouncy Castle's `CipherUtilities`, and its case does not
matter. The OIDs are NIST's for AES-128, AES-192 and AES-256 in each mode; as in Bouncy Castle,
those of ECB and CBC mean PKCS#7 padding. All three find the same row, so the length of the key
comes from the params.

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
- `finalize` goes back to the same IV, as in Bouncy Castle. So give each message a new `init` with a
  new IV: a second message without one repeats the IV, which in OFB repeats the whole keystream and
  in CFB its first block. Nothing checks this, and `init` takes an IV it has seen before.
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

## Using it

- `encrypt_by_name` and `decrypt_by_name` take the whole message at once and give the whole
  result; `by_oid` does the same by OID.
- For a message in parts, `get_by_name` gives a `Cipher`: `init` with the direction and the
  params, then `update` for each part, then `finalize`. `output_len` tells how large a buffer the
  next call needs, for `process_bytes` and `do_final`.
- With no padding, ECB and CBC take whole blocks only: a message of another length is
  `DataLength` from `finalize`. CFB and OFB take any length.
- `reset` starts over with the same key and IV.
