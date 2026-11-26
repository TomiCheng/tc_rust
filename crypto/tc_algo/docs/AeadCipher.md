# AEAD ciphers

An AEAD cipher encrypts a message and adds a tag, which shows on decryption that nothing was changed.
The tag also covers associated data (AAD): data that stays readable, such as a header, but cannot be
changed either.

From a new key to the decrypted message, with AES in GCM mode. The `aes` feature of `tc_algo` has
the row, and the nonce here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::params::{cipher::AeadParamsOwned, key::KeyOwned, key::KeyParams};
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
use tc_algo::params::{cipher::AeadParamsOwned, key::KeyOwned, key::KeyParams};
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

The AEAD modes of Bouncy Castle's `CipherUtilities`, GCM, CCM, EAX and OCB, and two more of
`tc_aead_cipher` it does not name, GCM-SIV and KCCM, take a block cipher of their block size:

| Mode | Block | Nonce bytes | Tag bytes |
|---|---|---|---|
| GCM | 16 bytes | 1.. | 4..16 |
| CCM | 16 bytes | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| EAX | 8, 16 bytes | .. | 4..block |
| OCB | 16 bytes | ..15 | 8..16 |
| GCM-SIV | 16 bytes | 12 | 16 |
| KCCM | 16, 32, 64 bytes | ..block | 8, 16, 32, 48, 64 |

So each algorithm of a block of 16 bytes has the six, each of a block of 8 bytes has EAX alone, and
Threefish-256, Threefish-512, DSTU7624-256 and DSTU7624-512 have KCCM. `block` is the block of the
algorithm in bytes, and the tag of KCCM is no longer than a block; the table of rows below gives
each row its own numbers.
Sizes are lists (`8, 16`), ranges with both ends included (`4..16`), with no lower end (`..15`),
with no upper end (`1..`), or of any length (`..`).

GCM-SIV, of RFC 8452, resists the reuse of a nonce: a repeated nonce shows only whether two
messages are equal, where in GCM it gives the key of the tag away. KCCM, of DSTU 7624, the CCM of
Ukraine, takes messages and AAD of whole blocks only; a partial block is `DataLength`, and its
counter is of 4 bytes, the standard's default. Their names, `GCM-SIV` and `KCCM`, are this crate's.
The feature of the algorithm has its rows, and the key is the algorithm's; see
[Block ciphers](BlockCipher.md).

Some AEAD ciphers are algorithms of their own, not modes of a block cipher. Bouncy Castle's
`CipherUtilities` names the two ChaCha ones; the lightweight ones, of NIST's competition, have the
names of their designers.

ChaCha20-Poly1305 is that of RFC 8439, and its OID that of RFC 8103. XChaCha20-Poly1305 takes a
nonce of 24 bytes, long enough to draw at random for every message.

Ascon-AEAD128 is the standard of NIST SP 800-232. ASCON-128, ASCON-128A and ASCON-80PQ are the
variants of Ascon v1.2 that it supersedes, for data made before it; they are not the standard, and
do not interoperate with it. Grain-128AEAD and Schwaemm, the AEAD of the Sparkle family, were
finalists of the competition; SCHWAEMM256-128 is Sparkle's primary member.

All of these are constant time.

Every row, of a mode or of an algorithm of its own:

| Name | Aliases | OIDs | Params | Feature | Key bytes | Nonce bytes | Tag bytes |
|---|---|---|---|---|---|---|---|
| `AES/GCM/NOPADDING` | `AES/GCM/`, `AES/GCM` | `2.16.840.1.101.3.4.1.6`, `.26`, `.46` | `AeadParamsOwned` | `aes` | 16, 24, 32 | 1.. | 4..16 |
| `AES/CCM/NOPADDING` | `AES/CCM/`, `AES/CCM` | `2.16.840.1.101.3.4.1.7`, `.27`, `.47` | `AeadParamsOwned` | `aes` | 16, 24, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `AES/EAX/NOPADDING` | `AES/EAX/`, `AES/EAX` |  | `AeadParamsOwned` | `aes` | 16, 24, 32 | .. | 4..16 |
| `AES/OCB/NOPADDING` | `AES/OCB/`, `AES/OCB` |  | `AeadParamsOwned` | `aes` | 16, 24, 32 | ..15 | 8..16 |
| `AES/GCM-SIV/NOPADDING` | `AES/GCM-SIV/`, `AES/GCM-SIV` |  | `AeadParamsOwned` | `aes` | 16, 24, 32 | 12 | 16 |
| `AES/KCCM/NOPADDING` | `AES/KCCM/`, `AES/KCCM` |  | `AeadParamsOwned` | `aes` | 16, 24, 32 | ..16 | 8, 16 |
| `ARIA/GCM/NOPADDING` | `ARIA/GCM/`, `ARIA/GCM` | `1.2.410.200046.1.1.34`, `.35`, `.36` | `AeadParamsOwned` | `aria` | 16, 24, 32 | 1.. | 4..16 |
| `ARIA/CCM/NOPADDING` | `ARIA/CCM/`, `ARIA/CCM` | `1.2.410.200046.1.1.37`, `.38`, `.39` | `AeadParamsOwned` | `aria` | 16, 24, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `ARIA/EAX/NOPADDING` | `ARIA/EAX/`, `ARIA/EAX` |  | `AeadParamsOwned` | `aria` | 16, 24, 32 | .. | 4..16 |
| `ARIA/OCB/NOPADDING` | `ARIA/OCB/`, `ARIA/OCB` |  | `AeadParamsOwned` | `aria` | 16, 24, 32 | ..15 | 8..16 |
| `ARIA/GCM-SIV/NOPADDING` | `ARIA/GCM-SIV/`, `ARIA/GCM-SIV` |  | `AeadParamsOwned` | `aria` | 16, 24, 32 | 12 | 16 |
| `ARIA/KCCM/NOPADDING` | `ARIA/KCCM/`, `ARIA/KCCM` |  | `AeadParamsOwned` | `aria` | 16, 24, 32 | ..16 | 8, 16 |
| `CAMELLIA/GCM/NOPADDING` | `CAMELLIA/GCM/`, `CAMELLIA/GCM` |  | `AeadParamsOwned` | `camellia` | 16, 24, 32 | 1.. | 4..16 |
| `CAMELLIA/CCM/NOPADDING` | `CAMELLIA/CCM/`, `CAMELLIA/CCM` |  | `AeadParamsOwned` | `camellia` | 16, 24, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `CAMELLIA/EAX/NOPADDING` | `CAMELLIA/EAX/`, `CAMELLIA/EAX` |  | `AeadParamsOwned` | `camellia` | 16, 24, 32 | .. | 4..16 |
| `CAMELLIA/OCB/NOPADDING` | `CAMELLIA/OCB/`, `CAMELLIA/OCB` |  | `AeadParamsOwned` | `camellia` | 16, 24, 32 | ..15 | 8..16 |
| `CAMELLIA/GCM-SIV/NOPADDING` | `CAMELLIA/GCM-SIV/`, `CAMELLIA/GCM-SIV` |  | `AeadParamsOwned` | `camellia` | 16, 24, 32 | 12 | 16 |
| `CAMELLIA/KCCM/NOPADDING` | `CAMELLIA/KCCM/`, `CAMELLIA/KCCM` |  | `AeadParamsOwned` | `camellia` | 16, 24, 32 | ..16 | 8, 16 |
| `SM4/GCM/NOPADDING` | `SM4/GCM/`, `SM4/GCM` |  | `AeadParamsOwned` | `sm4` | 16 | 1.. | 4..16 |
| `SM4/CCM/NOPADDING` | `SM4/CCM/`, `SM4/CCM` |  | `AeadParamsOwned` | `sm4` | 16 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `SM4/EAX/NOPADDING` | `SM4/EAX/`, `SM4/EAX` |  | `AeadParamsOwned` | `sm4` | 16 | .. | 4..16 |
| `SM4/OCB/NOPADDING` | `SM4/OCB/`, `SM4/OCB` |  | `AeadParamsOwned` | `sm4` | 16 | ..15 | 8..16 |
| `SM4/GCM-SIV/NOPADDING` | `SM4/GCM-SIV/`, `SM4/GCM-SIV` |  | `AeadParamsOwned` | `sm4` | 16 | 12 | 16 |
| `SM4/KCCM/NOPADDING` | `SM4/KCCM/`, `SM4/KCCM` |  | `AeadParamsOwned` | `sm4` | 16 | ..16 | 8, 16 |
| `SEED/GCM/NOPADDING` | `SEED/GCM/`, `SEED/GCM` |  | `AeadParamsOwned` | `seed` | 16 | 1.. | 4..16 |
| `SEED/CCM/NOPADDING` | `SEED/CCM/`, `SEED/CCM` |  | `AeadParamsOwned` | `seed` | 16 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `SEED/EAX/NOPADDING` | `SEED/EAX/`, `SEED/EAX` |  | `AeadParamsOwned` | `seed` | 16 | .. | 4..16 |
| `SEED/OCB/NOPADDING` | `SEED/OCB/`, `SEED/OCB` |  | `AeadParamsOwned` | `seed` | 16 | ..15 | 8..16 |
| `SEED/GCM-SIV/NOPADDING` | `SEED/GCM-SIV/`, `SEED/GCM-SIV` |  | `AeadParamsOwned` | `seed` | 16 | 12 | 16 |
| `SEED/KCCM/NOPADDING` | `SEED/KCCM/`, `SEED/KCCM` |  | `AeadParamsOwned` | `seed` | 16 | ..16 | 8, 16 |
| `TWOFISH/GCM/NOPADDING` | `TWOFISH/GCM/`, `TWOFISH/GCM` |  | `AeadParamsOwned` | `twofish` | 16, 24, 32 | 1.. | 4..16 |
| `TWOFISH/CCM/NOPADDING` | `TWOFISH/CCM/`, `TWOFISH/CCM` |  | `AeadParamsOwned` | `twofish` | 16, 24, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `TWOFISH/EAX/NOPADDING` | `TWOFISH/EAX/`, `TWOFISH/EAX` |  | `AeadParamsOwned` | `twofish` | 16, 24, 32 | .. | 4..16 |
| `TWOFISH/OCB/NOPADDING` | `TWOFISH/OCB/`, `TWOFISH/OCB` |  | `AeadParamsOwned` | `twofish` | 16, 24, 32 | ..15 | 8..16 |
| `TWOFISH/GCM-SIV/NOPADDING` | `TWOFISH/GCM-SIV/`, `TWOFISH/GCM-SIV` |  | `AeadParamsOwned` | `twofish` | 16, 24, 32 | 12 | 16 |
| `TWOFISH/KCCM/NOPADDING` | `TWOFISH/KCCM/`, `TWOFISH/KCCM` |  | `AeadParamsOwned` | `twofish` | 16, 24, 32 | ..16 | 8, 16 |
| `SERPENT/GCM/NOPADDING` | `SERPENT/GCM/`, `SERPENT/GCM` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | 1.. | 4..16 |
| `SERPENT/CCM/NOPADDING` | `SERPENT/CCM/`, `SERPENT/CCM` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `SERPENT/EAX/NOPADDING` | `SERPENT/EAX/`, `SERPENT/EAX` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | .. | 4..16 |
| `SERPENT/OCB/NOPADDING` | `SERPENT/OCB/`, `SERPENT/OCB` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | ..15 | 8..16 |
| `SERPENT/GCM-SIV/NOPADDING` | `SERPENT/GCM-SIV/`, `SERPENT/GCM-SIV` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | 12 | 16 |
| `SERPENT/KCCM/NOPADDING` | `SERPENT/KCCM/`, `SERPENT/KCCM` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | ..16 | 8, 16 |
| `TNEPRES/GCM/NOPADDING` | `TNEPRES/GCM/`, `TNEPRES/GCM` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | 1.. | 4..16 |
| `TNEPRES/CCM/NOPADDING` | `TNEPRES/CCM/`, `TNEPRES/CCM` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `TNEPRES/EAX/NOPADDING` | `TNEPRES/EAX/`, `TNEPRES/EAX` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | .. | 4..16 |
| `TNEPRES/OCB/NOPADDING` | `TNEPRES/OCB/`, `TNEPRES/OCB` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | ..15 | 8..16 |
| `TNEPRES/GCM-SIV/NOPADDING` | `TNEPRES/GCM-SIV/`, `TNEPRES/GCM-SIV` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | 12 | 16 |
| `TNEPRES/KCCM/NOPADDING` | `TNEPRES/KCCM/`, `TNEPRES/KCCM` |  | `AeadParamsOwned` | `serpent` | 4..32, by 4 | ..16 | 8, 16 |
| `CAST6/GCM/NOPADDING` | `CAST6/GCM/`, `CAST6/GCM` |  | `AeadParamsOwned` | `cast` | 16, 20, 24, 28, 32 | 1.. | 4..16 |
| `CAST6/CCM/NOPADDING` | `CAST6/CCM/`, `CAST6/CCM` |  | `AeadParamsOwned` | `cast` | 16, 20, 24, 28, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `CAST6/EAX/NOPADDING` | `CAST6/EAX/`, `CAST6/EAX` |  | `AeadParamsOwned` | `cast` | 16, 20, 24, 28, 32 | .. | 4..16 |
| `CAST6/OCB/NOPADDING` | `CAST6/OCB/`, `CAST6/OCB` |  | `AeadParamsOwned` | `cast` | 16, 20, 24, 28, 32 | ..15 | 8..16 |
| `CAST6/GCM-SIV/NOPADDING` | `CAST6/GCM-SIV/`, `CAST6/GCM-SIV` |  | `AeadParamsOwned` | `cast` | 16, 20, 24, 28, 32 | 12 | 16 |
| `CAST6/KCCM/NOPADDING` | `CAST6/KCCM/`, `CAST6/KCCM` |  | `AeadParamsOwned` | `cast` | 16, 20, 24, 28, 32 | ..16 | 8, 16 |
| `NOEKEON/GCM/NOPADDING` | `NOEKEON/GCM/`, `NOEKEON/GCM` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | 1.. | 4..16 |
| `NOEKEON/CCM/NOPADDING` | `NOEKEON/CCM/`, `NOEKEON/CCM` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `NOEKEON/EAX/NOPADDING` | `NOEKEON/EAX/`, `NOEKEON/EAX` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | .. | 4..16 |
| `NOEKEON/OCB/NOPADDING` | `NOEKEON/OCB/`, `NOEKEON/OCB` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | ..15 | 8..16 |
| `NOEKEON/GCM-SIV/NOPADDING` | `NOEKEON/GCM-SIV/`, `NOEKEON/GCM-SIV` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | 12 | 16 |
| `NOEKEON/KCCM/NOPADDING` | `NOEKEON/KCCM/`, `NOEKEON/KCCM` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | ..16 | 8, 16 |
| `RIJNDAEL/GCM/NOPADDING` | `RIJNDAEL/GCM/`, `RIJNDAEL/GCM` |  | `AeadParamsOwned` | `misc-block-cipher` | 16, 20, 24, 28, 32 | 1.. | 4..16 |
| `RIJNDAEL/CCM/NOPADDING` | `RIJNDAEL/CCM/`, `RIJNDAEL/CCM` |  | `AeadParamsOwned` | `misc-block-cipher` | 16, 20, 24, 28, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `RIJNDAEL/EAX/NOPADDING` | `RIJNDAEL/EAX/`, `RIJNDAEL/EAX` |  | `AeadParamsOwned` | `misc-block-cipher` | 16, 20, 24, 28, 32 | .. | 4..16 |
| `RIJNDAEL/OCB/NOPADDING` | `RIJNDAEL/OCB/`, `RIJNDAEL/OCB` |  | `AeadParamsOwned` | `misc-block-cipher` | 16, 20, 24, 28, 32 | ..15 | 8..16 |
| `RIJNDAEL/GCM-SIV/NOPADDING` | `RIJNDAEL/GCM-SIV/`, `RIJNDAEL/GCM-SIV` |  | `AeadParamsOwned` | `misc-block-cipher` | 16, 20, 24, 28, 32 | 12 | 16 |
| `RIJNDAEL/KCCM/NOPADDING` | `RIJNDAEL/KCCM/`, `RIJNDAEL/KCCM` |  | `AeadParamsOwned` | `misc-block-cipher` | 16, 20, 24, 28, 32 | ..16 | 8, 16 |
| `RC6/GCM/NOPADDING` | `RC6/GCM/`, `RC6/GCM` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | 1.. | 4..16 |
| `RC6/CCM/NOPADDING` | `RC6/CCM/`, `RC6/CCM` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `RC6/EAX/NOPADDING` | `RC6/EAX/`, `RC6/EAX` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | .. | 4..16 |
| `RC6/OCB/NOPADDING` | `RC6/OCB/`, `RC6/OCB` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | ..15 | 8..16 |
| `RC6/GCM-SIV/NOPADDING` | `RC6/GCM-SIV/`, `RC6/GCM-SIV` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | 12 | 16 |
| `RC6/KCCM/NOPADDING` | `RC6/KCCM/`, `RC6/KCCM` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | ..16 | 8, 16 |
| `RC5-64/GCM/NOPADDING` | `RC5-64/GCM/`, `RC5-64/GCM` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc5ParamsOwned>`](Key/Rc5ParamsOwned.md) | `rc-cipher` | 1..255 | 1.. | 4..16 |
| `RC5-64/CCM/NOPADDING` | `RC5-64/CCM/`, `RC5-64/CCM` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc5ParamsOwned>`](Key/Rc5ParamsOwned.md) | `rc-cipher` | 1..255 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `RC5-64/EAX/NOPADDING` | `RC5-64/EAX/`, `RC5-64/EAX` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc5ParamsOwned>`](Key/Rc5ParamsOwned.md) | `rc-cipher` | 1..255 | .. | 4..16 |
| `RC5-64/OCB/NOPADDING` | `RC5-64/OCB/`, `RC5-64/OCB` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc5ParamsOwned>`](Key/Rc5ParamsOwned.md) | `rc-cipher` | 1..255 | ..15 | 8..16 |
| `RC5-64/GCM-SIV/NOPADDING` | `RC5-64/GCM-SIV/`, `RC5-64/GCM-SIV` |  | `AeadParamsOwned` | `rc-cipher` | 1..255 | 12 | 16 |
| `RC5-64/KCCM/NOPADDING` | `RC5-64/KCCM/`, `RC5-64/KCCM` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc5ParamsOwned>`](Key/Rc5ParamsOwned.md) | `rc-cipher` | 1..255 | ..16 | 8, 16 |
| `DSTU7624-128/GCM/NOPADDING` | `DSTU7624-128/GCM/`, `DSTU7624-128/GCM` |  | `AeadParamsOwned` | `dstu7624` | 16, 32 | 1.. | 4..16 |
| `DSTU7624-128/CCM/NOPADDING` | `DSTU7624-128/CCM/`, `DSTU7624-128/CCM` |  | `AeadParamsOwned` | `dstu7624` | 16, 32 | 7..13 | 4, 6, 8, 10, 12, 14, 16 |
| `DSTU7624-128/EAX/NOPADDING` | `DSTU7624-128/EAX/`, `DSTU7624-128/EAX` |  | `AeadParamsOwned` | `dstu7624` | 16, 32 | .. | 4..16 |
| `DSTU7624-128/OCB/NOPADDING` | `DSTU7624-128/OCB/`, `DSTU7624-128/OCB` |  | `AeadParamsOwned` | `dstu7624` | 16, 32 | ..15 | 8..16 |
| `DSTU7624-128/GCM-SIV/NOPADDING` | `DSTU7624-128/GCM-SIV/`, `DSTU7624-128/GCM-SIV` |  | `AeadParamsOwned` | `dstu7624` | 16, 32 | 12 | 16 |
| `DSTU7624-128/KCCM/NOPADDING` | `DSTU7624-128/KCCM/`, `DSTU7624-128/KCCM` |  | `AeadParamsOwned` | `dstu7624` | 16, 32 | ..16 | 8, 16 |
| `DES/EAX/NOPADDING` | `DES/EAX/`, `DES/EAX` |  | `AeadParamsOwned` | `des` | 8 | .. | 4..8 |
| `DESEDE/EAX/NOPADDING` | `TDEA/EAX/NOPADDING`, `DESEDE/EAX/`, `DESEDE/EAX`, `TDEA/EAX/`, `TDEA/EAX` |  | `AeadParamsOwned` | `des` | 16, 24 | .. | 4..8 |
| `BLOWFISH/EAX/NOPADDING` | `BLOWFISH/EAX/`, `BLOWFISH/EAX` |  | `AeadParamsOwned` | `blowfish` | 4..56 | .. | 4..8 |
| `CAST5/EAX/NOPADDING` | `CAST5/EAX/`, `CAST5/EAX` |  | `AeadParamsOwned` | `cast` | 5..16 | .. | 4..8 |
| `IDEA/EAX/NOPADDING` | `IDEA/EAX/`, `IDEA/EAX` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | .. | 4..8 |
| `SKIPJACK/EAX/NOPADDING` | `SKIPJACK/EAX/`, `SKIPJACK/EAX` |  | `AeadParamsOwned` | `misc-block-cipher` | 10 | .. | 4..8 |
| `TEA/EAX/NOPADDING` | `TEA/EAX/`, `TEA/EAX` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | .. | 4..8 |
| `XTEA/EAX/NOPADDING` | `XTEA/EAX/`, `XTEA/EAX` |  | `AeadParamsOwned` | `misc-block-cipher` | 16 | .. | 4..8 |
| `RC2/EAX/NOPADDING` | `RC2/EAX/`, `RC2/EAX` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc2ParamsOwned>`](Key/Rc2ParamsOwned.md) | `rc-cipher` | 1..128 | .. | 4..8 |
| `RC5/EAX/NOPADDING` | `RC5-32/EAX/NOPADDING`, `RC5/EAX/`, `RC5/EAX`, `RC5-32/EAX/`, `RC5-32/EAX` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Rc5ParamsOwned>`](Key/Rc5ParamsOwned.md) | `rc-cipher` | 1..255 | .. | 4..8 |
| `GOST28147/EAX/NOPADDING` | `GOST/EAX/NOPADDING`, `GOST-28147/EAX/NOPADDING`, `GOST28147/EAX/`, `GOST28147/EAX`, `GOST/EAX/`, `GOST/EAX`, `GOST-28147/EAX/`, `GOST-28147/EAX` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<Gost28147ParamsOwned>`](Key/Gost28147ParamsOwned.md) | `gost28147` | 32 | .. | 4..8 |
| `THREEFISH-256/KCCM/NOPADDING` | `THREEFISH-256/KCCM/`, `THREEFISH-256/KCCM` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<ThreefishParamsOwned>`](Key/ThreefishParamsOwned.md) | `threefish` | 32 | ..32 | 8, 16, 32 |
| `THREEFISH-512/KCCM/NOPADDING` | `THREEFISH-512/KCCM/`, `THREEFISH-512/KCCM` |  | `AeadParamsOwned`, [`ParamsWithAeadOwned<ThreefishParamsOwned>`](Key/ThreefishParamsOwned.md) | `threefish` | 64 | ..64 | 8, 16, 32, 48, 64 |
| `DSTU7624-256/KCCM/NOPADDING` | `DSTU7624-256/KCCM/`, `DSTU7624-256/KCCM` |  | `AeadParamsOwned` | `dstu7624` | 32, 64 | ..32 | 8, 16, 32 |
| `DSTU7624-512/KCCM/NOPADDING` | `DSTU7624-512/KCCM/`, `DSTU7624-512/KCCM` |  | `AeadParamsOwned` | `dstu7624` | 64 | ..64 | 8, 16, 32, 48, 64 |
| `CHACHA20-POLY1305` |  | `1.2.840.113549.1.9.16.3.18` | `AeadParamsOwned` | `chacha-aead` | 32 | 12 | 16 |
| `XCHACHA20-POLY1305` |  |  | `AeadParamsOwned` | `chacha-aead` | 32 | 24 | 16 |
| `ASCON-AEAD128` |  |  | `AeadParamsOwned` | `ascon-aead` | 16 | 16 | 4..16 |
| `ASCON-128` |  |  | `AeadParamsOwned` | `ascon-aead` | 16 | 16 | 16 |
| `ASCON-128A` |  |  | `AeadParamsOwned` | `ascon-aead` | 16 | 16 | 16 |
| `ASCON-80PQ` |  |  | `AeadParamsOwned` | `ascon-aead` | 20 | 16 | 16 |
| `GRAIN-128AEAD` |  |  | `AeadParamsOwned` | `grain128-aead` | 16 | 12 | 8 |
| `SCHWAEMM128-128` |  |  | `AeadParamsOwned` | `sparkle-aead` | 16 | 16 | 16 |
| `SCHWAEMM256-128` |  |  | `AeadParamsOwned` | `sparkle-aead` | 16 | 32 | 16 |
| `SCHWAEMM192-192` |  |  | `AeadParamsOwned` | `sparkle-aead` | 24 | 24 | 24 |
| `SCHWAEMM256-256` |  |  | `AeadParamsOwned` | `sparkle-aead` | 32 | 32 | 32 |

There is no `AES/GCM/PKCS7PADDING`. An AEAD mode needs no padding, and Bouncy Castle refuses any but
`NOPADDING`, `RAW` among them; the names that leave the padding out or empty find the row.

The OIDs are NIST's and NSRI's for 128-, 192- and 256-bit keys. All three find the same row, so the
length of the key comes from the params: `id-aes128-GCM` does not refuse a 32-byte key. They also
find the key generator of their key length.

## Params

Every row takes an `AeadParamsOwned`. The rows of RC2, RC5, GOST 28147 and Threefish also take a
`ParamsWithAeadOwned` of the algorithm's own params, as the Params column links. Any other type is
`InvalidParams`, and so is a key the algorithm does not take, or a nonce or tag size outside the
table of its mode.

- `AeadParamsOwned::new(key, nonce, mac_size, initial_aad)` holds a bare key.
- `ParamsWithAeadOwned::new(own, nonce, mac_size, initial_aad)` holds the own params instead, such
  as an `Rc2ParamsOwned` with another effective key size; the mode gives the engine those alone.
  GCM-SIV derives its message keys from the key bytes, so `RC5-64/GCM-SIV` takes a bare key only.
- `mac_size` is in bytes, not in bits as in Bouncy Castle.
- `initial_aad` may be empty. All of the AAD goes in here, since `Cipher` has no call to add more.
- Both wipe the nonce and the AAD when dropped; the key, or the own params, wipe themselves.

## The nonce

- Never encrypt two messages under one key and nonce. Doing so reveals how the two messages differ,
  and lets an attacker forge tags under that key.
- `init` refuses to encrypt with the key and nonce of the previous `init` of the same instance, as
  `InvalidParams`. Nothing tracks them across instances, so keeping them apart is up to the caller.
- With random nonces of 12 bytes in GCM, stop at 2^32 messages under one key (NIST SP 800-38D).
- The nonce is not secret: send it along with the ciphertext, since decrypting needs the same one.
  The same goes for the AAD, which is not part of the output.

## Using it

- `get_by_name` and `get_by_oid` give a `Cipher`, which is a `BufferedCipher` and a
  `BufferedCipherInit` of `tc_buffered_cipher` with `AlgoError` for its errors, so code written
  for those traits takes it as it is.
- A wrong tag, a changed AAD, or a ciphertext too short to hold the tag is `InvalidCiphertext`. They
  are not told apart.
- As in Bouncy Castle, `update` may give plaintext before `finalize` has checked the tag. Use none of
  it, and discard it, when `finalize` fails. The helpers do this for you.
- `update` and `finalize` give `NotInitialized` before an `init` that succeeded, and after an
  encryption has finished: the next message takes a new `init`, with a new nonce.
- Each mode is as constant time as the block cipher under it. `tc_aes::AesEngine` is constant time
  with AES-NI or with its `rustcrypto` feature, and variable time otherwise; the notes of
  [Block ciphers](BlockCipher.md) give the others.
