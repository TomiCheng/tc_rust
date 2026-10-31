# Ciphers

`tc_algo::cipher` creates ciphers by name or by OID, after Bouncy Castle's
`CipherUtilities`. Every cipher it creates is an `AnyCipher`, whatever its kind:

- [Block ciphers](#block-ciphers), in a mode with a padding: AES and DES.
- [Stream ciphers](#stream-ciphers), with neither a mode nor a padding: ChaCha,
  Salsa20, RC4, VMPC and HC.
- [AEAD ciphers](#aead-ciphers), which authenticate what they encrypt: the AEAD
  modes of the block ciphers.
- [IES ciphers](#ies-ciphers): none yet.
- [Asymmetric ciphers](#asymmetric-ciphers): RSA.

## Enabling ciphers

Each cipher has its own Cargo feature, listed in the table of its kind. AES, ChaCha,
Salsa20 and RSA are in the default features. DES, RC4 and VMPC are weak, and HC is
not constant time, so they are opt-in. Modes and paddings need no feature: every
cipher comes with all of its own.

```toml
[dependencies]
# Add weak ciphers for compatibility with old data
tc_algo = { version = "0.1", features = ["des", "rc4"] }

# Or keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["aes"] }
```

## Usage

### In four steps

Get a cipher, initialize it, feed it, then finish. `init` takes the direction and the
params: the key, and whatever else the cipher needs, such as an IV. `finalize`
returns the rest of the output, with the padding or the tag.

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

`init` refuses a field the cipher has no use for, such as an IV for ECB or any field
for RSA, and a missing field it needs, such as the IV for CBC, both with
`InvalidParams`.

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

### By name or OID

A name is the whole transformation, `ALGORITHM/MODE/PADDING`. As in Bouncy Castle,
names match without regard to ASCII case, `-` and `_` are the same, and aliases are
accepted. What a missing mode or padding gives depends on the kind, as its section
says. The cipher reports its canonical name.

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

`get_by_oid` takes an `Asn1Oid`.

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

## Block ciphers

A block cipher runs in a mode, with a padding. `init` takes a secret key, and an IV
of one block for every mode but ECB. A missing mode is ECB, and a missing padding is
the mode's default.

| Algorithm | Key | Mode | OID | Feature | Default | Padding |
|---|---|---|---|---|:---:|---|
| AES | 128 | ECB | 2.16.840.1.101.3.4.1.1 | `aes` | ✓ | PKCS7PADDING |
| AES | 192 | ECB | 2.16.840.1.101.3.4.1.21 | `aes` | ✓ | PKCS7PADDING |
| AES | 256 | ECB | 2.16.840.1.101.3.4.1.41 | `aes` | ✓ | PKCS7PADDING |
| AES | 128 | CBC | 2.16.840.1.101.3.4.1.2 | `aes` | ✓ | PKCS7PADDING |
| AES | 192 | CBC | 2.16.840.1.101.3.4.1.22 | `aes` | ✓ | PKCS7PADDING |
| AES | 256 | CBC | 2.16.840.1.101.3.4.1.42 | `aes` | ✓ | PKCS7PADDING |
| AES | 128 | CFB | 2.16.840.1.101.3.4.1.4 | `aes` | ✓ | NOPADDING |
| AES | 192 | CFB | 2.16.840.1.101.3.4.1.24 | `aes` | ✓ | NOPADDING |
| AES | 256 | CFB | 2.16.840.1.101.3.4.1.44 | `aes` | ✓ | NOPADDING |
| AES | 128 | OFB | 2.16.840.1.101.3.4.1.3 | `aes` | ✓ | NOPADDING |
| AES | 192 | OFB | 2.16.840.1.101.3.4.1.23 | `aes` | ✓ | NOPADDING |
| AES | 256 | OFB | 2.16.840.1.101.3.4.1.43 | `aes` | ✓ | NOPADDING |
| AES | 128, 192, 256 | CTR | | `aes` | ✓ | NOPADDING |
| DES | 64 | ECB | 1.3.14.3.2.6 | `des` | | PKCS7PADDING |
| DES | 64 | CBC | 1.3.14.3.2.7 | `des` | | PKCS7PADDING |
| DES | 64 | CFB | 1.3.14.3.2.9 | `des` | | NOPADDING |
| DES | 64 | OFB | 1.3.14.3.2.8 | `des` | | NOPADDING |
| DES | 64 | CTR | | `des` | | NOPADDING |

Key is in bits. Padding is the one the row's OID gives; on a row without an OID, it is
the default.

Every mode takes every padding by name: NOPADDING, PKCS7PADDING, ISO10126PADDING,
ISO7816-4PADDING, X923PADDING, TBCPADDING and ZEROBYTEPADDING.

The key size in an AES OID is not checked: each of the three finds the same cipher,
such as AES/CBC/PKCS7PADDING, which takes a key of any AES size. The rows without an
OID have none in Bouncy Castle either.

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
- **ISO10126PADDING** fills with random bytes from the operating system.
- **ZEROBYTEPADDING** removes every trailing zero byte on decryption, so a plaintext
  that ends in zero bytes does not come back whole.

## Stream ciphers

A stream cipher takes neither a mode nor a padding: its name is the algorithm alone.
`init` takes a secret key and, for every cipher but ARC4, an IV. Each `update` gives
as many bytes as it takes, and `finalize` gives none.

```rust
use tc_algo::AlgoError;
use tc_algo::cipher;
use tc_algo::params::{AnyKeyParams, AnyParams, SecretKey};

fn main() -> Result<(), AlgoError> {
    let key = SecretKey::new(rand::random::<[u8; 32]>().to_vec());
    let mut params = AnyParams::new(AnyKeyParams::Secret(key));
    params.op.iv = Some(rand::random::<[u8; 24]>().to_vec());

    let ciphertext = cipher::encrypt("XCHACHA20", &params, b"hello, world")?;
    let plaintext = cipher::decrypt("XCHACHA20", &params, &ciphertext)?;
    Ok(())
}
```

| Algorithm | Key | IV | OID | Feature | Default |
|---|---|---|---|---|:---:|
| CHACHA | 128, 256 | 64 | | `chacha` | ✓ |
| CHACHA7539 | 256 | 96 | | `chacha` | ✓ |
| XCHACHA20 | 256 | 192 | | `chacha` | ✓ |
| SALSA20 | 128, 256 | 64 | | `salsa20` | ✓ |
| ARC4 | 8 to 2048 | | 1.2.840.113549.3.4 | `rc4` | |
| VMPC | 128 to 512 | 128 to 512 | | `vmpc` | |
| VMPC-KSA3 | 128 to 512 | 128 to 512 | | `vmpc` | |
| HC128 | 128 | 128 | | `hc` | |
| HC256 | 128, 256 | 128 or more | | `hc` | |

Key and IV are in bits, in whole bytes. HC256 reads the first 256 bits of a longer
IV, as Bouncy Castle does. The rows without an OID have none in Bouncy Castle either.

### Notes

- **Aliases**: CHACHA20 for CHACHA7539; RC4 and ARCFOUR for ARC4.
- **CHACHA** is Bernstein's original ChaCha20, with a 64-bit IV. **CHACHA7539** is
  that of RFC 8439, with a 96-bit IV and a 32-bit block counter, so one key and IV
  encrypt at most 256 GiB; past that, it fails with `DataLength`. **XCHACHA20** has
  an IV long enough to be drawn at random for each message.
- **No authentication**: a stream cipher does not see a change to the ciphertext,
  and a bit flipped in the ciphertext flips the same bit of the plaintext. Use an
  AEAD cipher to protect a message.
- **A key and IV once only**: two messages under the same key and IV give away the
  XOR of their plaintexts. As in Bouncy Castle, `finalize` starts the keystream over,
  so init again with a new IV for each message.
- **RC4, VMPC and HC** look up tables of secret state, so their timing can leak the
  key through the cache. They are here for compatibility with Bouncy Castle. RC4 is
  also biased, which is why RFC 7465 bans it from TLS.

## AEAD ciphers

An AEAD cipher authenticates what it encrypts. For now these are the AEAD modes of
the block ciphers. `init` takes a secret key, the nonce in `iv`, the tag length in
bytes in `tag_len`, and optionally associated data in `aad`. Encryption appends the
tag to the ciphertext; decryption fails with `InvalidCiphertext` if anything was
changed.

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

| Algorithm | Key | Mode | OID | Feature | Default |
|---|---|---|---|---|:---:|
| AES | 128 | CCM | 2.16.840.1.101.3.4.1.7 | `aes` | ✓ |
| AES | 192 | CCM | 2.16.840.1.101.3.4.1.27 | `aes` | ✓ |
| AES | 256 | CCM | 2.16.840.1.101.3.4.1.47 | `aes` | ✓ |
| AES | 128 | GCM | 2.16.840.1.101.3.4.1.6 | `aes` | ✓ |
| AES | 192 | GCM | 2.16.840.1.101.3.4.1.26 | `aes` | ✓ |
| AES | 256 | GCM | 2.16.840.1.101.3.4.1.46 | `aes` | ✓ |
| AES | 128, 192, 256 | EAX, OCB | | `aes` | ✓ |
| DES | 64 | EAX | | `des` | |

Key is in bits. Every row takes only NOPADDING, which is also its default. EAX runs
on 64- and 128-bit blocks, but CCM, GCM and OCB only on 128-bit blocks, so DES has
EAX alone. As for the block ciphers, the key size in an AES OID is not checked.

### Notes

- **GCM encryption** takes a new `init` with a new nonce after each `finalize`, so
  that no nonce is used twice under one key.

## IES ciphers

No IES cipher is in the table yet.

## Asymmetric ciphers

An asymmetric cipher takes a key of its algorithm, public or private, and no other
field. It encrypts one block: the message must fit in the modulus less what the
padding takes, and the ciphertext is as long as the modulus. It has no mode, written
NONE. A missing padding is NOPADDING, as in Bouncy Castle.

```rust
use tc_algo::AlgoError;
use tc_algo::cipher;
use tc_algo::generate;
use tc_algo::params::{AnyKeyParams, AnyParams};

fn main() -> Result<(), AlgoError> {
    let keys = generate::generate_key_pair("RSA")?;
    let public = AnyParams::new(AnyKeyParams::Public(keys.public));
    let private = AnyParams::new(AnyKeyParams::Private(keys.private));

    let name = "RSA/NONE/OAEPWITHSHA256ANDMGF1PADDING";
    let ciphertext = cipher::encrypt(name, &public, b"hello, world")?;
    let plaintext = cipher::decrypt(name, &private, &ciphertext)?;
    Ok(())
}
```

| Algorithm | Padding | OID | Feature | Default |
|---|---|---|---|:---:|
| RSA | NOPADDING | | `rsa` | ✓ |
| RSA | PKCS1PADDING | 1.2.840.113549.1.1.1 | `rsa` | ✓ |
| RSA | OAEPWITHSHA1ANDMGF1PADDING | 1.2.840.113549.1.1.7 | `rsa` | ✓ |
| RSA | OAEPWITHSHA224ANDMGF1PADDING | | `rsa` | ✓ |
| RSA | OAEPWITHSHA256ANDMGF1PADDING | | `rsa` | ✓ |
| RSA | OAEPWITHSHA256ANDMGF1WITHSHA1PADDING | | `rsa` | ✓ |
| RSA | OAEPWITHSHA384ANDMGF1PADDING | | `rsa` | ✓ |
| RSA | OAEPWITHSHA512ANDMGF1PADDING | | `rsa` | ✓ |

Every row takes an RSA key of any size. The first hash of an OAEP name hashes the
label, the second, if any, is that of MGF1.

### Notes

- **Aliases**: ECB or no mode at all for NONE; PKCS1 for PKCS1PADDING; OAEPPADDING
  and OAEP for OAEPWITHSHA1ANDMGF1PADDING; and SHA-1, SHA-256 and so on for SHA1,
  SHA256 in the OAEP names.
- **RSA without a padding** is raw RSA, which is deterministic and malleable. `"RSA"`
  alone is RSA/NONE/NOPADDING, as in Bouncy Castle, so name the padding.
- **PKCS1PADDING** decryption tells whether the padding was good, which Bleichenbacher's
  attack turns into decryption. Where an attacker can send ciphertexts, use OAEP.
- **OAEP with SHA-1** is still sound, as OAEP does not rest on collisions, so it comes
  with `rsa` rather than with the `sha1` digest feature.
- **RSA keys** work in either direction, as in Bouncy Castle: PKCS1PADDING with the
  private key gives a block of type 1. The private key is blinded, so that its power
  never works on the ciphertext itself.
