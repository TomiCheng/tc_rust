# AEAD ciphers

An AEAD cipher encrypts a message and adds a tag, which shows on decryption that nothing was changed.
The tag also covers associated data (AAD): data that stays readable, such as a header, but cannot be
changed either.

From a new key to the decrypted message, with AES in GCM mode. The `aes` feature of `tc_algo_v2` has
the row, and the nonce here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo_v2::params::{AeadParamsOwned, KeyOwned, KeyParams};
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "AES/GCM/NOPADDING";
    let message = b"attack at dawn";
    let aad = b"message 1";

    // Generate a key
    let key = algo.key_generator().generate_by_name("AES256")?;
    let key = key
        .as_any()
        .downcast_ref::<KeyOwned>()
        .expect("AES256 generates a KeyOwned");

    // Set a new nonce, the size of the tag and the AAD
    let mut nonce = vec![0; 12];
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    let params = AeadParamsOwned::new(key.key().to_vec(), nonce, 16, aad.to_vec());

    // Encrypt: the output is the ciphertext, then the tag
    let sealed = algo.cipher().encrypt_by_name(name, &params, message)?;

    // Decrypt: a wrong tag is an error, and no plaintext comes out
    let opened = algo.cipher().decrypt_by_name(name, &params, &sealed)?;

    assert_eq!(opened, message);
    Ok(())
}
```

The same in pieces, when the message does not come all at once:

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo_v2::cipher::CipherDirection;
use tc_algo_v2::params::{AeadParamsOwned, KeyOwned, KeyParams};
use tc_algo_v2::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let name = "AES/GCM/NOPADDING";

    let key = algo.key_generator().generate_by_name("AES256")?;
    let key = key
        .as_any()
        .downcast_ref::<KeyOwned>()
        .expect("AES256 generates a KeyOwned");
    let mut nonce = vec![0; 12];
    UnwrapErr(SysRng).fill_bytes(&mut nonce);
    let params = AeadParamsOwned::new(key.key().to_vec(), nonce, 16, b"message 1".to_vec());

    // Encrypt
    let mut cipher = algo.cipher().get_by_name(name)?;
    cipher.init(CipherDirection::Encrypt, &params)?;
    let mut sealed = cipher.update(b"attack ")?;
    sealed.extend(cipher.update(b"at dawn")?);
    sealed.extend(cipher.finalize()?);

    // Decrypt: what update gives does not count until finalize has checked the tag
    let mut cipher = algo.cipher().get_by_name(name)?;
    cipher.init(CipherDirection::Decrypt, &params)?;
    let mut opened = cipher.update(&sealed)?;
    opened.extend(cipher.finalize()?);

    assert_eq!(opened, b"attack at dawn");
    Ok(())
}
```

## Algorithms

| Name | OIDs | Feature | Key bytes | Nonce bytes | Tag bytes |
|---|---|---|---|---|---|
| `AES/GCM/NOPADDING` | `2.16.840.1.101.3.4.1.6`, `.26`, `.46` | `aes` | 16, 24, 32 | 1 or more; use 12 | 4 to 16; use 16 |

There is no `AES/GCM/PKCS7PADDING`. GCM needs no padding, and Bouncy Castle refuses one too.

The three OIDs are `id-aes128-GCM`, `id-aes192-GCM` and `id-aes256-GCM`. All of them find the same
row, so the length of the key comes from the params: `id-aes128-GCM` does not refuse a 32-byte key.
They also find the key generator of their key length.

## Params

The row takes an `AeadParamsOwned`, and any other type is `InvalidParams`. So is a key, nonce or tag
size outside the table. `AeadParamsOwned::new(key, nonce, mac_size, initial_aad)` holds them:

- `mac_size` is in bytes, not in bits as in Bouncy Castle.
- `initial_aad` may be empty. All of the AAD goes in here, since `Cipher` has no call to add more.
- It wipes itself when dropped.

## The nonce

- Never encrypt two messages under one key and nonce. Doing so reveals how the two messages differ,
  and lets an attacker forge tags under that key.
- `init` refuses to encrypt with the key and nonce of the previous `init` of the same instance, as
  `InvalidParams`. Nothing tracks them across instances, so keeping them apart is up to the caller.
- With random nonces of 12 bytes, stop at 2^32 messages under one key (NIST SP 800-38D).
- The nonce is not secret: send it along with the ciphertext, since decrypting needs the same one.
  The same goes for the AAD, which is not part of the output.

## Using it

- A wrong tag, a changed AAD, or a ciphertext too short to hold the tag is `InvalidCiphertext`. They
  are not told apart.
- As in Bouncy Castle, `update` may give plaintext before `finalize` has checked the tag. Use none of
  it, and discard it, when `finalize` fails. The helpers do this for you.
- `update` and `finalize` give `NotInitialized` before an `init` that succeeded, and after an
  encryption has finished: the next message takes a new `init`, with a new nonce.
- GCM is as constant time as the AES under it. `tc_aes::AesEngine` is constant time with AES-NI or
  with its `rustcrypto` feature, and variable time otherwise.
