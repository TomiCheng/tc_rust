# PBE

Password-based encryption protects data with a password. A cipher wants a key that is random and of a
fixed length, while a person remembers a short string, so PBE turns the password into the params of
a cipher. It does not encrypt anything itself, and it is not a way of encrypting passwords.

```text
password + salt + iteration count -> PBE -> key + IV -> cipher -> ciphertext
```

From a password to the decrypted message. The `pbe-aes` feature of `tc_algo` has the rows, and the
salt here comes from `rand` and `rand_core`.

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

| Name | OID | Feature | Key bytes | IV bytes | Target |
|---|---|---|---|---|---|
| `PBEwithSHA-256and128bitAES-CBC-BC` | `1.3.6.1.4.1.22554.1.2.1.2.1.2` | `pbe-aes` | 16 | 16 | `AES/CBC/PKCS7PADDING` |
| `PBEwithSHA-256and192bitAES-CBC-BC` | `1.3.6.1.4.1.22554.1.2.1.2.1.22` | `pbe-aes` | 24 | 16 | `AES/CBC/PKCS7PADDING` |
| `PBEwithSHA-256and256bitAES-CBC-BC` | `1.3.6.1.4.1.22554.1.2.1.2.1.42` | `pbe-aes` | 32 | 16 | `AES/CBC/PKCS7PADDING` |

`PBEWITHSHA256AND128BITAES-CBC-BC` and its like find them too, and the case of a name does not
matter. The names and OIDs are those of Bouncy Castle's `PbeUtilities`, and all three use the PKCS#12
generator of RFC 7292 over SHA-256.

## The params

`generate_params` gives a `KeyWithIvOwned`, as used with any row of AES in CBC mode, and it wipes
itself when dropped. `target` names the row it is for, so nothing else needs to know the mode or
padding of the scheme.

## The inputs

- **Password.** Do not store it. A `&str`, since a scheme decides how to encode it: the PKCS#12
  generator encodes it as UTF-16. Wiping the `&str` is up to the caller.
- **Salt.** Use a new random one for each message, of at least 16 bytes. It is not secret: keep it with
  the ciphertext. The IV is derived too, so the same password and salt give the same key and the same
  IV, which is why a salt must not be used twice.
- **Iteration count.** It makes each guess at the password slower, for an attacker and for you alike.
  It is not secret: keep it with the ciphertext. Only 0 is refused, as `InvalidParams`, so choosing one
  high enough is up to the caller.

## Using it

- **It is only as strong as the password.** A count slows guessing down, but a short or common password
  still falls.
- **CBC does not detect a changed ciphertext.** Authenticate the ciphertext before decrypting it.
- A wrong password usually shows as `InvalidCiphertext` from the padding, but not always: by chance it
  can give garbage with valid padding. Do not take a successful decryption as proof of the password.
- For a secret that is already random, as from an agreement, use a KDF such as HKDF. PBE is for
  passwords, and is slow on purpose.
- To store a password and check it later, use a password hash instead: PBE is for encrypting data.
- PBES2, whose KDF and cipher are named in ASN.1 params, has no row here.
