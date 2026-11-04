# MACs

`tc_algo::mac` creates message authentication codes by name or by OID. Every MAC it
creates is an `AnyMac`.

## Enabling MACs

A MAC appears when every feature in its row of [the table](#algorithms) is on. The default
features include `hmac`, `cmac`, `cbc-mac`, `cfb-mac` and `siphash`, but not the weak digests
and ciphers, so they give HMAC-SHA-256 and AESCMAC but not HMAC-MD5 or DESMAC.

```toml
[dependencies]
# HMAC-MD5 and DESMAC for compatibility with old data
tc_algo = { version = "0.1", features = ["md5", "des"] }

# Or keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["hmac", "sha256"] }
```

## Usage

### In three steps

Find a MAC, initialize it with the key, feed it, then finish. `finalize` returns the
tag and starts the next message under the same key, so another message needs no new
`init`. AES-GMAC and POLY1305 are the exceptions: each needs a new `init` for each message.

```rust
use tc_algo::AlgoError;
use tc_algo::mac::{self, AnyMacParams};
use tc_algo::params::SecretKey;

fn main() -> Result<(), AlgoError> {
    let params = AnyMacParams::new(SecretKey::new(b"a secret key".to_vec()));

    let mut hmac = mac::get_by_name("HMAC-SHA256")?;
    hmac.init(&params)?;
    hmac.update(b"hello, ")?;
    hmac.update(b"world")?;
    let tag = hmac.finalize()?;
    assert_eq!(tag.len(), hmac.mac_size());
    Ok(())
}
```

### In one step

```rust
use tc_algo::AlgoError;
use tc_algo::mac::{self, AnyMacParams};
use tc_algo::params::SecretKey;

fn main() -> Result<(), AlgoError> {
    let params = AnyMacParams::new(SecretKey::new(b"a secret key".to_vec()));
    let tag = mac::calculate("HMAC-SHA256", &params, b"hello, world")?;
    assert_eq!(tag.len(), 32);
    Ok(())
}
```

### Checking a tag you received

Use `verify` rather than `==`. It compares in constant time, whereas `==` on slices
stops at the first difference, which tells an attacker how much of a forged tag is
right. After it, the MAC goes on as it does after `finalize`.

```rust
use tc_algo::AlgoError;
use tc_algo::mac::{self, AnyMacParams};
use tc_algo::params::SecretKey;

fn main() -> Result<(), AlgoError> {
    let params = AnyMacParams::new(SecretKey::new(b"a secret key".to_vec()));
    let received = mac::calculate("HMAC-SHA256", &params, b"hello, world")?;

    let mut hmac = mac::get_by_name("HMAC-SHA256")?;
    hmac.init(&params)?;
    hmac.update(b"hello, world")?;
    assert!(hmac.verify(&received)?);
    Ok(())
}
```

### By name or OID

Names match without regard to ASCII case, and a string that is not a name is parsed
as a dotted OID. `get_by_oid` takes an `Asn1Oid`. The MAC reports its canonical name.

```rust
use tc_algo::mac;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let hmac = mac::get_by_name("hmac/sha256")?;
    assert_eq!(hmac.entry().name(), "HMAC-SHA-256");

    let by_oid = mac::get_by_name("1.2.840.113549.2.9")?;
    assert_eq!(by_oid.entry().name(), "HMAC-SHA-256");

    let error = mac::get_by_name("NO-SUCH-MAC").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownMac);
    Ok(())
}
```

### Looking at the table

```rust
use tc_algo::mac;

for entry in mac::algorithms() {
    println!("{entry}"); // e.g. `HMAC-SHA-256  [id-hmacWithSHA256]`
}
```

## Params

`AnyMacParams` holds the key and, for the MACs that take one, an IV. It is plain data:
`init` checks it. A field the MAC has no use for is refused with `InvalidParams`, not
ignored, so HMAC refuses an IV.

```rust
use tc_algo::AlgoError;
use tc_algo::mac::{self, AnyMacParams};
use tc_algo::params::SecretKey;

fn main() -> Result<(), AlgoError> {
    let key = SecretKey::new(vec![0x42; 16]);
    let params = AnyMacParams::new(key).with_iv(vec![0x24; 16]);
    let tag = mac::calculate("VMPCMAC", &params, b"hello, world")?;
    assert_eq!(tag.len(), 20);
    Ok(())
}
```

## Errors

| `ErrorKind` | When |
|---|---|
| `UnknownMac` | No row has that name or OID, or its feature is off |
| `InvalidParams` | `init` was given a field the MAC refuses, or one of the wrong length |
| `NotInitialized` | `update` or `finalize` came before a successful `init` |
| `DataLength` | The buffer given to `Mac::do_final` is shorter than the tag |

A failed `init` leaves the MAC uninitialized, so it never goes on under an earlier key.

## Algorithms

| Name | OID | Tag bytes | IV bytes | Features |
|---|---|---:|---|---|
| HMAC-MD2 | — | 16 | — | `hmac`, `md2` |
| HMAC-MD4 | — | 16 | — | `hmac`, `md4` |
| HMAC-MD5 | `1.3.6.1.5.5.8.1.1` | 16 | — | `hmac`, `md5` |
| HMAC-SHA-1 | `1.2.840.113549.2.7`, `1.3.6.1.5.5.8.1.2` | 20 | — | `hmac`, `sha1` |
| HMAC-SHA-224 | `1.2.840.113549.2.8` | 28 | — | `hmac`, `sha224` |
| HMAC-SHA-256 | `1.2.840.113549.2.9` | 32 | — | `hmac`, `sha256` |
| HMAC-SHA-384 | `1.2.840.113549.2.10` | 48 | — | `hmac`, `sha384` |
| HMAC-SHA-512 | `1.2.840.113549.2.11` | 64 | — | `hmac`, `sha512` |
| HMAC-SHA-512/224 | `1.2.840.113549.2.12` | 28 | — | `hmac`, `sha512-224` |
| HMAC-SHA-512/256 | `1.2.840.113549.2.13` | 32 | — | `hmac`, `sha512-256` |
| HMAC-SHA3-224 | `2.16.840.1.101.3.4.2.13` | 28 | — | `hmac`, `sha3-224` |
| HMAC-SHA3-256 | `2.16.840.1.101.3.4.2.14` | 32 | — | `hmac`, `sha3-256` |
| HMAC-SHA3-384 | `2.16.840.1.101.3.4.2.15` | 48 | — | `hmac`, `sha3-384` |
| HMAC-SHA3-512 | `2.16.840.1.101.3.4.2.16` | 64 | — | `hmac`, `sha3-512` |
| HMAC-KECCAK-224 | — | 28 | — | `hmac`, `keccak-224` |
| HMAC-KECCAK-256 | — | 32 | — | `hmac`, `keccak-256` |
| HMAC-KECCAK-288 | — | 36 | — | `hmac`, `keccak-288` |
| HMAC-KECCAK-384 | — | 48 | — | `hmac`, `keccak-384` |
| HMAC-KECCAK-512 | — | 64 | — | `hmac`, `keccak-512` |
| HMAC-SHAKE128-256 | — | 32 | — | `hmac`, `shake128` |
| HMAC-SHAKE256-512 | — | 64 | — | `hmac`, `shake256` |
| HMAC-BLAKE2B-160 | — | 20 | — | `hmac`, `blake2b-160` |
| HMAC-BLAKE2B-256 | — | 32 | — | `hmac`, `blake2b-256` |
| HMAC-BLAKE2B-384 | — | 48 | — | `hmac`, `blake2b-384` |
| HMAC-BLAKE2B-512 | — | 64 | — | `hmac`, `blake2b-512` |
| HMAC-BLAKE2S-128 | — | 16 | — | `hmac`, `blake2s-128` |
| HMAC-BLAKE2S-160 | — | 20 | — | `hmac`, `blake2s-160` |
| HMAC-BLAKE2S-224 | — | 28 | — | `hmac`, `blake2s-224` |
| HMAC-BLAKE2S-256 | — | 32 | — | `hmac`, `blake2s-256` |
| HMAC-BLAKE3-256 | — | 32 | — | `hmac`, `blake3-256` |
| HMAC-DSTU7564-256 | — | 32 | — | `hmac`, `dstu7564-256` |
| HMAC-DSTU7564-384 | — | 48 | — | `hmac`, `dstu7564-384` |
| HMAC-DSTU7564-512 | — | 64 | — | `hmac`, `dstu7564-512` |
| HMAC-GOST3411 | — | 32 | — | `hmac`, `gost3411` |
| HMAC-GOST3411-2012-256 | `1.2.643.7.1.1.4.1` | 32 | — | `hmac`, `gost3411-2012-256` |
| HMAC-GOST3411-2012-512 | `1.2.643.7.1.1.4.2` | 64 | — | `hmac`, `gost3411-2012-512` |
| HMAC-RIPEMD128 | — | 16 | — | `hmac`, `ripemd128` |
| HMAC-RIPEMD160 | `1.3.6.1.5.5.8.1.4` | 20 | — | `hmac`, `ripemd160` |
| HMAC-RIPEMD256 | — | 32 | — | `hmac`, `ripemd256` |
| HMAC-RIPEMD320 | — | 40 | — | `hmac`, `ripemd320` |
| HMAC-SM3 | — | 32 | — | `hmac`, `sm3` |
| HMAC-TIGER | `1.3.6.1.5.5.8.1.3` | 24 | — | `hmac`, `tiger` |
| HMAC-WHIRLPOOL | — | 64 | — | `hmac`, `whirlpool` |
| AESCMAC | — | 16 | — | `cmac`, `aes` |
| AES-GMAC | — | 16 | 1 or more, required | `gmac`, `aes` |
| DESMAC | — | 4 | 8, optional | `cbc-mac`, `des` |
| DESMAC/CFB8 | — | 4 | 8, optional | `cfb-mac`, `des` |
| DESMAC64 | — | 8 | 8, optional | `cbc-mac`, `des` |
| DESEDECMAC | — | 8 | — | `cmac`, `desede` |
| DESEDEMAC | `1.2.840.113549.3.7` | 4 | 8, optional | `cbc-mac`, `desede` |
| DESEDEMAC/CFB8 | — | 4 | 8, optional | `cfb-mac`, `desede` |
| DESEDEMAC64 | — | 8 | 8, optional | `cbc-mac`, `desede` |
| DESEDEMAC64WITHISO7816-4PADDING | — | 8 | 8, optional | `cbc-mac`, `desede` |
| SKIPJACKMAC | — | 4 | 8, optional | `cbc-mac`, `skipjack` |
| SKIPJACKMAC/CFB8 | — | 4 | 8, optional | `cfb-mac`, `skipjack` |
| IDEAMAC | — | 4 | 8, optional | `cbc-mac`, `idea` |
| IDEAMAC/CFB8 | — | 4 | 8, optional | `cfb-mac`, `idea` |
| RC2MAC | — | 4 | 8, optional | `cbc-mac`, `rc2` |
| RC2MAC/CFB8 | — | 4 | 8, optional | `cfb-mac`, `rc2` |
| RC5MAC | — | 4 | 8, optional | `cbc-mac`, `rc5` |
| RC5MAC/CFB8 | — | 4 | 8, optional | `cfb-mac`, `rc5` |
| ISO9797ALG3MAC | — | 8 | 8, optional | `iso9797-mac` |
| ISO9797ALG3WITHISO7816-4PADDING | — | 8 | 8, optional | `iso9797-mac` |
| GOST28147MAC | — | 4 | 8, optional | `gost28147-mac` |
| VMPCMAC | — | 20 | 16 to 64, required | `vmpc-mac` |
| SIPHASH-2-4 | — | 8 | — | `siphash` |
| POLY1305 | — | 16 | — | `poly1305` |
| KMAC128 | `2.16.840.1.101.3.4.2.21`, `2.16.840.1.101.3.4.2.19` | 32 | — | `kmac` |
| KMAC256 | `2.16.840.1.101.3.4.2.22`, `2.16.840.1.101.3.4.2.20` | 64 | — | `kmac` |
| DSTU7564MAC-256 | `1.2.804.2.1.1.1.1.2.2.4` | 32 | — | `dstu7564-mac` |
| DSTU7564MAC-384 | `1.2.804.2.1.1.1.1.2.2.5` | 48 | — | `dstu7564-mac` |
| DSTU7564MAC-512 | `1.2.804.2.1.1.1.1.2.2.6` | 64 | — | `dstu7564-mac` |
| DSTU7624MAC-128 | `1.2.804.2.1.1.1.1.3.4.1` | 16 | — | `dstu7624-mac` |
| DSTU7624MAC-256 | `1.2.804.2.1.1.1.1.3.4.2` | 32 | — | `dstu7624-mac` |
| DSTU7624MAC-512 | `1.2.804.2.1.1.1.1.3.4.3` | 64 | — | `dstu7624-mac` |
| Skein-MAC-256-128 | — | 16 | — | `skein-mac` |
| Skein-MAC-256-160 | — | 20 | — | `skein-mac` |
| Skein-MAC-256-224 | — | 28 | — | `skein-mac` |
| Skein-MAC-256-256 | — | 32 | — | `skein-mac` |
| Skein-MAC-512-128 | — | 16 | — | `skein-mac` |
| Skein-MAC-512-160 | — | 20 | — | `skein-mac` |
| Skein-MAC-512-224 | — | 28 | — | `skein-mac` |
| Skein-MAC-512-256 | — | 32 | — | `skein-mac` |
| Skein-MAC-512-384 | — | 48 | — | `skein-mac` |
| Skein-MAC-512-512 | — | 64 | — | `skein-mac` |
| Skein-MAC-1024-384 | — | 48 | — | `skein-mac` |
| Skein-MAC-1024-512 | — | 64 | — | `skein-mac` |
| Skein-MAC-1024-1024 | — | 128 | — | `skein-mac` |

### Names

Names match without regard to ASCII case. An HMAC is `HMAC-`, `HMAC/` or `HMAC` before any
name of its digest, so `HMAC-SHA256` and `HMACSHA256` find HMAC-SHA-256. The others also go
by shorter names: `DES` finds DESMAC, and `SIPHASH` finds SIPHASH-2-4.

### IV

A MAC with `—` refuses an IV. An optional IV left out is the same as a block of zeros.

### Choosing

- CBC-MAC and CFB-MAC are secure only for messages of one fixed length. Where lengths vary,
  use HMAC or CMAC.
- SipHash's 8-byte tag suits hash tables and other short-lived authenticators, not general
  use.
- AES-GMAC's nonce must never repeat under one key. `init` refuses the last key and nonce
  again, but cannot see further back.
- A POLY1305 key is good for one message. Use a new key each time.
- DSTU7624MAC takes whole blocks only: any other length gives `DataLength` from `finalize`.
