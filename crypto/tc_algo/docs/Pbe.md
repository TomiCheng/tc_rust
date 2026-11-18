# PBE

Password-based encryption protects data with a password. A cipher wants a key that is random and of a
fixed length, while a person remembers a short string, so PBE turns the password into the params of
a cipher. It does not encrypt anything itself, and it is not a way of encrypting passwords.

```text
password + salt + iteration count -> PBE -> key + IV -> cipher -> ciphertext
```

From a password to the decrypted message. The `pbe`, `sha` and `aes` features of `tc_algo` have
the row, and the salt here comes from `rand` and `rand_core`.

```rust
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use tc_algo::{AlgoBuilder, AlgoError, DefaultAlgoBuilder};

fn main() -> Result<(), AlgoError> {
    let algo = DefaultAlgoBuilder::default().build();
    let password = "correct horse battery staple";
    let message = b"attack at dawn";

    // A new salt for each message, and a count that makes guessing slow
    let mut salt = [0; 16];
    UnwrapErr(SysRng).fill_bytes(&mut salt);
    let iterations = 100_000;

    // The password gives the params of a cipher
    let pbe = algo.pbe().get_by_name("PBEWITHSHA256AND256BITAES-CBC-BC")?;
    let params = pbe.generate_params(password, &salt, iterations)?;

    // The row named by target encrypts
    let sealed = algo.cipher().encrypt_by_name(pbe.target(), params.as_ref(), message)?;

    // Keep the salt and the count with the ciphertext. Later, the password gives the same params
    let params = pbe.generate_params(password, &salt, iterations)?;
    let opened = algo.cipher().decrypt_by_name(pbe.target(), params.as_ref(), &sealed)?;

    assert_eq!(opened, message);
    Ok(())
}
```

## Algorithms

The names, aliases and OIDs are those of Bouncy Castle's `PbeUtilities`, and the case of a name does
not matter. A row is there when the `pbe` feature and those of its digest and of its cipher or HMAC
are on, as `pbe`, `sha` and `des` for `PBEwithSHA-1and3-keyDESEDE-CBC`.

- **PKCS#12**, of RFC 7292, the scheme of PKCS#12 files. Over SHA-256: AES-128, -192 and -256 in
  CBC mode, as `PBEwithSHA-256and256bitAES-CBC-BC`. Over SHA-1: the same AES, 3-key and 2-key
  DESede, RC2 of 128 and 40 bits in CBC mode, and RC4 of 128 and 40 bits, as
  `PBEwithSHA-1and3-keyDESEDE-CBC`, with the OIDs of RFC 7292 and Bouncy Castle.
- **PKCS#5 v1**, of RFC 8018: MD2, MD5 or SHA-1 with DES or RC2 in CBC mode, as
  `PBEwithMD5andDES-CBC`. Its key is 8 bytes, so it is for old data only.
- **OpenSSL**, the `EVP_BytesToKey` of `openssl enc` over MD5: AES-128, -192 and -256 in CBC mode,
  as `PBEwithMD5and256bitAES-CBC-OpenSSL`, for files that tool made. It has no OID, and it ignores
  the iteration count.
- **HMAC keys**, by PKCS#12: `PBEwithHmacSHA-1`, `-224`, `-256`, `-384` and `-512`,
  `PBEwithHmacRipeMD128`, `160` and `256`, and `PBEwithHmacTiger`, with the `macs` feature. Their
  OID is that of the digest, as in Bouncy Castle.

`PBEwithSHA-1andIDEA-CBC` and `PBEwithSHA-1andTWOFISH-CBC` are not here: Bouncy Castle names them
but generates no params for them.

## The params

`generate_params` gives what the row named by `target` takes, and it wipes itself when dropped:

- A `KeyWithIvOwned` for a cipher in CBC mode, with an IV of one block. The keys of DES and DESede
  get odd parity, as Bouncy Castle gives them, and RC2 takes the whole key as its effective key
  size.
- A `KeyOwned` for RC4, which has no IV, and for HMAC, as long as its digest.

`target` names the row of `algo.cipher()` or `algo.mac()`, as `AES/CBC/PKCS7PADDING` or
`HMAC-SHA256`, so nothing else needs to know the mode or padding of the scheme.

## The inputs

- **Password.** Do not store it. A `&str`, since a scheme decides how to encode it: PKCS#12 encodes
  it as UTF-16, while PKCS#5 v1 and OpenSSL keep the low byte of each UTF-16 unit, as Bouncy Castle
  does, so only an ASCII password keeps all of its bits there. Wiping the `&str` is up to the
  caller.
- **Salt.** Use a new random one for each message, of at least 16 bytes. It is not secret: keep it with
  the ciphertext. The IV is derived too, so the same password and salt give the same key and the same
  IV, which is why a salt must not be used twice.
- **Iteration count.** It makes each guess at the password slower, for an attacker and for you alike.
  It is not secret: keep it with the ciphertext. PKCS#12 and PKCS#5 v1 refuse only 0, as
  `InvalidParams`, so choosing one high enough is up to the caller. **OpenSSL ignores it** and runs
  once, as Bouncy Castle and `openssl enc` without `-pbkdf2` do, so its rows do nothing to slow
  guessing.

## Using it

- `get_by_name` and `get_by_oid` give a `Pbe`, a trait of this crate's own.
- **It is only as strong as the password.** A count slows guessing down, but a short or common password
  still falls.
- **CBC does not detect a changed ciphertext.** Authenticate the ciphertext before decrypting it.
- A wrong password usually shows as `InvalidCiphertext` from the padding, but not always: by chance it
  can give garbage with valid padding. Do not take a successful decryption as proof of the password.
- For a secret that is already random, as from an agreement, use a KDF such as HKDF. PBE is for
  passwords, and is slow on purpose.
- To store a password and check it later, use a password hash instead: PBE is for encrypting data.
- PBES2, whose KDF and cipher are named in ASN.1 params, has no row here.
