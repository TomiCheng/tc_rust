# AEAD ciphers

An AEAD cipher encrypts a message and adds a tag, which shows on decryption that nothing was changed.
The tag also covers associated data (AAD): data that stays readable, such as a header, but cannot be
changed either.

From a new key to the decrypted message, with AES in GCM mode. The `aes` feature of `tc_algo` has
the row, and the nonce here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{AeadParamsOwned, KeyOwned, KeyParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

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
use tc_algo::cipher::CipherDirection;
use tc_algo::params::{AeadParamsOwned, KeyOwned, KeyParams};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

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

The AEAD modes of Bouncy Castle's `CipherUtilities` take a block cipher of their block size:

| Mode | Block | Nonce bytes | Tag bytes |
|---|---|---|---|
| GCM | 16 bytes | 1 or more; use 12 | 4 to 16; use 16 |
| CCM | 16 bytes | 7 to 13 | 4 to 16, even |
| EAX | 8 or 16 bytes | any | 4 to a block |
| OCB | 16 bytes | up to 15; use 12 | 8 to 16 |

So each algorithm of a block of 16 bytes has the four, and each of a block of 8 bytes has EAX alone.
The feature of the algorithm has its rows, and the key is the algorithm's; see
[Block ciphers](BlockCipher.md).

| Name | Aliases | OIDs | Feature |
|---|---|---|---|
| `AES/GCM/NOPADDING` | `AES/GCM/`, `AES/GCM` | `2.16.840.1.101.3.4.1.6`, `.26`, `.46` | `aes` |
| `AES/CCM/NOPADDING` | `AES/CCM/`, `AES/CCM` | `2.16.840.1.101.3.4.1.7`, `.27`, `.47` | `aes` |
| `AES/EAX/NOPADDING` | `AES/EAX/`, `AES/EAX` |  | `aes` |
| `AES/OCB/NOPADDING` | `AES/OCB/`, `AES/OCB` |  | `aes` |
| `ARIA/GCM/NOPADDING` | `ARIA/GCM/`, `ARIA/GCM` | `1.2.410.200046.1.1.34`, `.35`, `.36` | `aria` |
| `ARIA/CCM/NOPADDING` | `ARIA/CCM/`, `ARIA/CCM` | `1.2.410.200046.1.1.37`, `.38`, `.39` | `aria` |
| `ARIA/EAX/NOPADDING` | `ARIA/EAX/`, `ARIA/EAX` |  | `aria` |
| `ARIA/OCB/NOPADDING` | `ARIA/OCB/`, `ARIA/OCB` |  | `aria` |
| `CAMELLIA/GCM/NOPADDING` | `CAMELLIA/GCM/`, `CAMELLIA/GCM` |  | `camellia` |
| `CAMELLIA/CCM/NOPADDING` | `CAMELLIA/CCM/`, `CAMELLIA/CCM` |  | `camellia` |
| `CAMELLIA/EAX/NOPADDING` | `CAMELLIA/EAX/`, `CAMELLIA/EAX` |  | `camellia` |
| `CAMELLIA/OCB/NOPADDING` | `CAMELLIA/OCB/`, `CAMELLIA/OCB` |  | `camellia` |
| `SM4/GCM/NOPADDING` | `SM4/GCM/`, `SM4/GCM` |  | `sm4` |
| `SM4/CCM/NOPADDING` | `SM4/CCM/`, `SM4/CCM` |  | `sm4` |
| `SM4/EAX/NOPADDING` | `SM4/EAX/`, `SM4/EAX` |  | `sm4` |
| `SM4/OCB/NOPADDING` | `SM4/OCB/`, `SM4/OCB` |  | `sm4` |
| `SEED/GCM/NOPADDING` | `SEED/GCM/`, `SEED/GCM` |  | `seed` |
| `SEED/CCM/NOPADDING` | `SEED/CCM/`, `SEED/CCM` |  | `seed` |
| `SEED/EAX/NOPADDING` | `SEED/EAX/`, `SEED/EAX` |  | `seed` |
| `SEED/OCB/NOPADDING` | `SEED/OCB/`, `SEED/OCB` |  | `seed` |
| `TWOFISH/GCM/NOPADDING` | `TWOFISH/GCM/`, `TWOFISH/GCM` |  | `twofish` |
| `TWOFISH/CCM/NOPADDING` | `TWOFISH/CCM/`, `TWOFISH/CCM` |  | `twofish` |
| `TWOFISH/EAX/NOPADDING` | `TWOFISH/EAX/`, `TWOFISH/EAX` |  | `twofish` |
| `TWOFISH/OCB/NOPADDING` | `TWOFISH/OCB/`, `TWOFISH/OCB` |  | `twofish` |
| `SERPENT/GCM/NOPADDING` | `SERPENT/GCM/`, `SERPENT/GCM` |  | `serpent` |
| `SERPENT/CCM/NOPADDING` | `SERPENT/CCM/`, `SERPENT/CCM` |  | `serpent` |
| `SERPENT/EAX/NOPADDING` | `SERPENT/EAX/`, `SERPENT/EAX` |  | `serpent` |
| `SERPENT/OCB/NOPADDING` | `SERPENT/OCB/`, `SERPENT/OCB` |  | `serpent` |
| `TNEPRES/GCM/NOPADDING` | `TNEPRES/GCM/`, `TNEPRES/GCM` |  | `tnepres` |
| `TNEPRES/CCM/NOPADDING` | `TNEPRES/CCM/`, `TNEPRES/CCM` |  | `tnepres` |
| `TNEPRES/EAX/NOPADDING` | `TNEPRES/EAX/`, `TNEPRES/EAX` |  | `tnepres` |
| `TNEPRES/OCB/NOPADDING` | `TNEPRES/OCB/`, `TNEPRES/OCB` |  | `tnepres` |
| `CAST6/GCM/NOPADDING` | `CAST6/GCM/`, `CAST6/GCM` |  | `cast6` |
| `CAST6/CCM/NOPADDING` | `CAST6/CCM/`, `CAST6/CCM` |  | `cast6` |
| `CAST6/EAX/NOPADDING` | `CAST6/EAX/`, `CAST6/EAX` |  | `cast6` |
| `CAST6/OCB/NOPADDING` | `CAST6/OCB/`, `CAST6/OCB` |  | `cast6` |
| `NOEKEON/GCM/NOPADDING` | `NOEKEON/GCM/`, `NOEKEON/GCM` |  | `noekeon` |
| `NOEKEON/CCM/NOPADDING` | `NOEKEON/CCM/`, `NOEKEON/CCM` |  | `noekeon` |
| `NOEKEON/EAX/NOPADDING` | `NOEKEON/EAX/`, `NOEKEON/EAX` |  | `noekeon` |
| `NOEKEON/OCB/NOPADDING` | `NOEKEON/OCB/`, `NOEKEON/OCB` |  | `noekeon` |
| `RIJNDAEL/GCM/NOPADDING` | `RIJNDAEL/GCM/`, `RIJNDAEL/GCM` |  | `rijndael` |
| `RIJNDAEL/CCM/NOPADDING` | `RIJNDAEL/CCM/`, `RIJNDAEL/CCM` |  | `rijndael` |
| `RIJNDAEL/EAX/NOPADDING` | `RIJNDAEL/EAX/`, `RIJNDAEL/EAX` |  | `rijndael` |
| `RIJNDAEL/OCB/NOPADDING` | `RIJNDAEL/OCB/`, `RIJNDAEL/OCB` |  | `rijndael` |
| `RC6/GCM/NOPADDING` | `RC6/GCM/`, `RC6/GCM` |  | `rc6` |
| `RC6/CCM/NOPADDING` | `RC6/CCM/`, `RC6/CCM` |  | `rc6` |
| `RC6/EAX/NOPADDING` | `RC6/EAX/`, `RC6/EAX` |  | `rc6` |
| `RC6/OCB/NOPADDING` | `RC6/OCB/`, `RC6/OCB` |  | `rc6` |
| `RC5-64/GCM/NOPADDING` | `RC5-64/GCM/`, `RC5-64/GCM` |  | `rc5-64` |
| `RC5-64/CCM/NOPADDING` | `RC5-64/CCM/`, `RC5-64/CCM` |  | `rc5-64` |
| `RC5-64/EAX/NOPADDING` | `RC5-64/EAX/`, `RC5-64/EAX` |  | `rc5-64` |
| `RC5-64/OCB/NOPADDING` | `RC5-64/OCB/`, `RC5-64/OCB` |  | `rc5-64` |
| `DES/EAX/NOPADDING` | `DES/EAX/`, `DES/EAX` |  | `des` |
| `DESEDE/EAX/NOPADDING` | `TDEA/EAX/NOPADDING`, `DESEDE/EAX/`, `DESEDE/EAX`, `TDEA/EAX/`, `TDEA/EAX` |  | `desede` |
| `BLOWFISH/EAX/NOPADDING` | `BLOWFISH/EAX/`, `BLOWFISH/EAX` |  | `blowfish` |
| `CAST5/EAX/NOPADDING` | `CAST5/EAX/`, `CAST5/EAX` |  | `cast5` |
| `IDEA/EAX/NOPADDING` | `IDEA/EAX/`, `IDEA/EAX` |  | `idea` |
| `SKIPJACK/EAX/NOPADDING` | `SKIPJACK/EAX/`, `SKIPJACK/EAX` |  | `skipjack` |
| `TEA/EAX/NOPADDING` | `TEA/EAX/`, `TEA/EAX` |  | `tea` |
| `XTEA/EAX/NOPADDING` | `XTEA/EAX/`, `XTEA/EAX` |  | `xtea` |
| `RC2/EAX/NOPADDING` | `RC2/EAX/`, `RC2/EAX` |  | `rc2` |
| `RC5/EAX/NOPADDING` | `RC5-32/EAX/NOPADDING`, `RC5/EAX/`, `RC5/EAX`, `RC5-32/EAX/`, `RC5-32/EAX` |  | `rc5` |
| `GOST28147/EAX/NOPADDING` | `GOST/EAX/NOPADDING`, `GOST-28147/EAX/NOPADDING`, `GOST28147/EAX/`, `GOST28147/EAX`, `GOST/EAX/`, `GOST/EAX`, `GOST-28147/EAX/`, `GOST-28147/EAX` |  | `gost28147` |

There is no `AES/GCM/PKCS7PADDING`. An AEAD mode needs no padding, and Bouncy Castle refuses any but
`NOPADDING`, `RAW` among them; the names that leave the padding out or empty find the row.

The OIDs are NIST's and NSRI's for 128-, 192- and 256-bit keys. All three find the same row, so the
length of the key comes from the params: `id-aes128-GCM` does not refuse a 32-byte key. They also
find the key generator of their key length.

## Params

The rows take an `AeadParamsOwned`, and any other type is `InvalidParams`. So is a key the algorithm
does not take, or a nonce or tag size outside the table of its mode. `AeadParamsOwned::new(key, nonce, mac_size, initial_aad)` holds them:

- `mac_size` is in bytes, not in bits as in Bouncy Castle.
- `initial_aad` may be empty. All of the AAD goes in here, since `Cipher` has no call to add more.
- It wipes itself when dropped.

## The nonce

- Never encrypt two messages under one key and nonce. Doing so reveals how the two messages differ,
  and lets an attacker forge tags under that key.
- `init` refuses to encrypt with the key and nonce of the previous `init` of the same instance, as
  `InvalidParams`. Nothing tracks them across instances, so keeping them apart is up to the caller.
- With random nonces of 12 bytes in GCM, stop at 2^32 messages under one key (NIST SP 800-38D).
- The nonce is not secret: send it along with the ciphertext, since decrypting needs the same one.
  The same goes for the AAD, which is not part of the output.

## Using it

- A wrong tag, a changed AAD, or a ciphertext too short to hold the tag is `InvalidCiphertext`. They
  are not told apart.
- As in Bouncy Castle, `update` may give plaintext before `finalize` has checked the tag. Use none of
  it, and discard it, when `finalize` fails. The helpers do this for you.
- `update` and `finalize` give `NotInitialized` before an `init` that succeeded, and after an
  encryption has finished: the next message takes a new `init`, with a new nonce.
- Each mode is as constant time as the block cipher under it. `tc_aes::AesEngine` is constant time
  with AES-NI or with its `rustcrypto` feature, and variable time otherwise; the notes of
  [Block ciphers](BlockCipher.md) give the others.
