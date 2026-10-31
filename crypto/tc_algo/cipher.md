# Ciphers

`tc_algo::cipher` creates ciphers by name or by OID, after Bouncy Castle's
`CipherUtilities`. Every cipher it creates is an `AnyCipher`.

## Enabling ciphers

Each block cipher has its own Cargo feature, listed in the [table](#algorithms) below.
AES is in the default features; DES is weak, so it is opt-in. Modes and paddings need
no feature: every block cipher comes with all of them.

```toml
[dependencies]
# Add a weak cipher for compatibility with old data
tc_algo = { version = "0.1", features = ["des"] }

# Or keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["aes"] }
```

## Usage

### In four steps

Get a cipher, initialize it, feed it, then finish. `init` takes the direction and the
params: the key, and the IV for every mode but ECB. `finalize` returns the rest of the
output, with the padding or the tag.

```rust
use tc_algo::AlgoError;
use tc_algo::cipher::{self, CipherDirection};
use tc_algo::generate;
use tc_algo::params::{AnyKeyParams, AnyParams};

fn main() -> Result<(), AlgoError> {
    let key = generate::generate_key("AES256")?;
    let mut params = AnyParams::new(AnyKeyParams::Secret(key));
    params.op.iv = Some(rand::random::<[u8; 16]>().to_vec());

    let mut aes = cipher::get_by_name("AES/CBC/PKCS7PADDING")?;
    aes.init(CipherDirection::Encrypt, &params)?;
    let mut ciphertext = aes.update(b"hello, ")?;
    ciphertext.extend(aes.update(b"world")?);
    ciphertext.extend(aes.finalize()?);
    Ok(())
}
```

### In one step

```rust
use tc_algo::AlgoError;
use tc_algo::cipher;
use tc_algo::generate;
use tc_algo::params::{AnyKeyParams, AnyParams};

fn main() -> Result<(), AlgoError> {
    let key = generate::generate_key("AES256")?;
    let mut params = AnyParams::new(AnyKeyParams::Secret(key));
    params.op.iv = Some(rand::random::<[u8; 16]>().to_vec());

    let ciphertext = cipher::encrypt("AES/CBC/PKCS7PADDING", &params, b"hello, world")?;
    let plaintext = cipher::decrypt("AES/CBC/PKCS7PADDING", &params, &ciphertext)?;
    Ok(())
}
```

### With an AEAD mode

An AEAD mode takes the nonce in `iv`, the tag length in bytes in `tag_len`, and
optionally associated data in `aad`. Encryption appends the tag to the ciphertext;
decryption fails with `InvalidCiphertext` if anything was changed.

```rust
use tc_algo::AlgoError;
use tc_algo::cipher;
use tc_algo::generate;
use tc_algo::params::{AnyKeyParams, AnyParams};

fn main() -> Result<(), AlgoError> {
    let key = generate::generate_key("AES256")?;
    let mut params = AnyParams::new(AnyKeyParams::Secret(key));
    params.op.iv = Some(rand::random::<[u8; 12]>().to_vec());
    params.op.tag_len = Some(16);
    params.op.aad = Some(b"header".to_vec());

    let sealed = cipher::encrypt("AES/GCM/NOPADDING", &params, b"hello, world")?;
    let opened = cipher::decrypt("AES/GCM/NOPADDING", &params, &sealed)?;
    Ok(())
}
```

`init` refuses a field the mode has no use for, such as an IV for ECB or a tag
length for CBC, and a missing field the mode needs, both with `InvalidParams`.

### By name or OID

A name is the whole transformation, `ALGORITHM/MODE/PADDING`. As in Bouncy Castle,
names match without regard to ASCII case, `-` and `_` are the same, a missing mode
is ECB, a missing padding is the mode's default, and aliases are accepted. The
cipher reports its canonical name.

```rust
use tc_algo::cipher;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let aes = cipher::get_by_name("aes/cbc")?;
    assert_eq!(aes.entry().name(), "AES/CBC/PKCS7PADDING");

    let error = cipher::get_by_name("AES/GCM/PKCS7PADDING").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownCipher);
    Ok(())
}
```

`get_by_oid` takes an `Asn1Oid`. The OIDs of the three AES key sizes lead to the
same row: `id-aes128-CBC` and `id-aes256-CBC` both give `AES/CBC/PKCS7PADDING`,
which takes any AES key.

### Looking at the table

```rust
use tc_algo::cipher;

for entry in cipher::algorithms() {
    println!("{entry}"); // e.g. `AES/CBC/PKCS7PADDING  [id-aes128-CBC, id-aes192-CBC, id-aes256-CBC]`
}

let entry = cipher::get_by_name("AES/GCM").unwrap().entry();
let name = entry.name(); // "AES/GCM/NOPADDING"
let oids = entry.oids(); // id-aes128-GCM, id-aes192-GCM, id-aes256-GCM
```

### In generic code

`AnyCipher` implements `BufferedCipher` and `BufferedCipherInit<AnyParams>`, which
`tc_algo::cipher` re-exports, so it fits anywhere a `BufferedCipher` is expected,
without a `tc_buffered_cipher` dependency of your own. It is also `Send`. Its `Debug`
output shows only the name, never the key or the state, and its `Display` output is
the canonical name.

## Algorithms

| Algorithm | Key | Mode | OID | Feature | Padding |
|---|---|---|---|---|---|
| AES | 128 | ECB | 2.16.840.1.101.3.4.1.1 | `aes` | PKCS7PADDING |
| AES | 192 | ECB | 2.16.840.1.101.3.4.1.21 | `aes` | PKCS7PADDING |
| AES | 256 | ECB | 2.16.840.1.101.3.4.1.41 | `aes` | PKCS7PADDING |
| AES | 128 | CBC | 2.16.840.1.101.3.4.1.2 | `aes` | PKCS7PADDING |
| AES | 192 | CBC | 2.16.840.1.101.3.4.1.22 | `aes` | PKCS7PADDING |
| AES | 256 | CBC | 2.16.840.1.101.3.4.1.42 | `aes` | PKCS7PADDING |
| AES | 128 | CFB | 2.16.840.1.101.3.4.1.4 | `aes` | NOPADDING |
| AES | 192 | CFB | 2.16.840.1.101.3.4.1.24 | `aes` | NOPADDING |
| AES | 256 | CFB | 2.16.840.1.101.3.4.1.44 | `aes` | NOPADDING |
| AES | 128 | OFB | 2.16.840.1.101.3.4.1.3 | `aes` | NOPADDING |
| AES | 192 | OFB | 2.16.840.1.101.3.4.1.23 | `aes` | NOPADDING |
| AES | 256 | OFB | 2.16.840.1.101.3.4.1.43 | `aes` | NOPADDING |
| AES | 128 | CCM | 2.16.840.1.101.3.4.1.7 | `aes` | NOPADDING |
| AES | 192 | CCM | 2.16.840.1.101.3.4.1.27 | `aes` | NOPADDING |
| AES | 256 | CCM | 2.16.840.1.101.3.4.1.47 | `aes` | NOPADDING |
| AES | 128 | GCM | 2.16.840.1.101.3.4.1.6 | `aes` | NOPADDING |
| AES | 192 | GCM | 2.16.840.1.101.3.4.1.26 | `aes` | NOPADDING |
| AES | 256 | GCM | 2.16.840.1.101.3.4.1.46 | `aes` | NOPADDING |
| AES | 128, 192, 256 | CTR, EAX, OCB | | `aes` | NOPADDING |
| DES | 64 | ECB | 1.3.14.3.2.6 | `des` | PKCS7PADDING |
| DES | 64 | CBC | 1.3.14.3.2.7 | `des` | PKCS7PADDING |
| DES | 64 | CFB | 1.3.14.3.2.9 | `des` | NOPADDING |
| DES | 64 | OFB | 1.3.14.3.2.8 | `des` | NOPADDING |
| DES | 64 | CTR, EAX | | `des` | NOPADDING |

Key is in bits. Padding is the mode's default, the one a name without a padding and an
OID both give. ECB, CBC, CFB, OFB and CTR take every padding by name: NOPADDING,
PKCS7PADDING, ISO10126PADDING, ISO7816-4PADDING, X923PADDING, TBCPADDING and
ZEROBYTEPADDING. The AEAD modes take only NOPADDING. EAX runs on 64- and 128-bit
blocks, but CCM, GCM and OCB only on 128-bit blocks, so DES has EAX alone.

The key size in an AES OID is not checked: each of the three finds the same cipher,
such as AES/CBC/PKCS7PADDING, which takes a key of any AES size. The modes on the last
row of each algorithm have no OID in Bouncy Castle either.

### Notes

- **Default padding**: CFB, OFB and CTR take a partial last block, so they need none.
  `"AES"` alone is AES/ECB/PKCS7PADDING, which shows patterns of the plaintext in the
  ciphertext, so name the mode.
- **Aliases**: SIC for CTR; PKCS7, PKCS5PADDING and PKCS5 for PKCS7PADDING;
  ISO10126D2PADDING and ISO10126-2PADDING for ISO10126PADDING; ISO9797-1PADDING for
  ISO7816-4PADDING.
- **CBC without an IV** is refused, unlike Bouncy Castle, which runs it with a zero IV.
- **CFB and OFB** feed back a whole block: CFB-128 and OFB-128 for AES, CFB-64 and
  OFB-64 for DES.
- **DES** takes an 8-byte key. As in Bouncy Castle, it ignores the parity bits and
  accepts the weak and semi-weak keys.
- **GCM encryption** takes a new `init` with a new nonce after each `finalize`, so
  that no nonce is used twice under one key.
- **ISO10126PADDING** fills with random bytes from the operating system.
- **ZEROBYTEPADDING** removes every trailing zero byte on decryption, so a plaintext
  that ends in zero bytes does not come back whole.
