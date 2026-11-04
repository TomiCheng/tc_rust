# MACs

`tc_algo::mac` creates message authentication codes by name or by OID, after Bouncy
Castle's `MacUtilities`. Every MAC it creates is an `AnyMac`.

## Enabling MACs

HMAC has the `hmac` feature, which is on by default, and has a row for each digest
that is enabled. HMAC-MD5 therefore needs the `md5` feature as well, since the default
features leave the weak digests out.

```toml
[dependencies]
# HMAC-MD5 for compatibility with old data
tc_algo = { version = "0.1", features = ["md5"] }

# Or keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["hmac", "sha256"] }
```

## Usage

### In three steps

Find a MAC, initialize it with the key, feed it, then finish. `finalize` returns the
tag and starts the next message under the same key, so another message needs no new
`init`.

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
right. Like `finalize`, it starts the next message.

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

## Errors

| `ErrorKind` | When |
|---|---|
| `UnknownMac` | No row has that name or OID, or its feature is off |
| `InvalidParams` | `init` was given a field the MAC refuses, or one of the wrong length |
| `NotInitialized` | `update` or `finalize` came before a successful `init` |
| `DataLength` | The buffer given to `Mac::do_final` is shorter than the tag |

A failed `init` leaves the MAC uninitialized, so it never goes on under an earlier key.

## HMAC

A name is `HMAC-`, `HMAC/` or `HMAC` followed by any name of the digest, so
`HMAC-SHA-256`, `HMAC-SHA256`, `HMAC/SHA256` and `HMACSHA256` are the same MAC, as in
Bouncy Castle. The canonical name is `HMAC-` followed by the digest's canonical name.
Any key length is accepted; a key longer than the digest's block is hashed first.

Every digest of [the digest table](digest.md#algorithms) has a row except NONE, which
is not a hash. These have OIDs, as in Bouncy Castle:

| MAC | OID | Name of the OID |
|---|---|---|
| HMAC-MD5 | `1.3.6.1.5.5.8.1.1` | hmacMD5 |
| HMAC-SHA-1 | `1.2.840.113549.2.7` | id-hmacWithSHA1 |
| HMAC-SHA-1 | `1.3.6.1.5.5.8.1.2` | hmac-sha1 |
| HMAC-SHA-224 | `1.2.840.113549.2.8` | id-hmacWithSHA224 |
| HMAC-SHA-256 | `1.2.840.113549.2.9` | id-hmacWithSHA256 |
| HMAC-SHA-384 | `1.2.840.113549.2.10` | id-hmacWithSHA384 |
| HMAC-SHA-512 | `1.2.840.113549.2.11` | id-hmacWithSHA512 |
| HMAC-SHA-512/224 | `1.2.840.113549.2.12` | id-hmacWithSHA512-224 |
| HMAC-SHA-512/256 | `1.2.840.113549.2.13` | id-hmacWithSHA512-256 |
| HMAC-SHA3-224 | `2.16.840.1.101.3.4.2.13` | id-hmacWithSHA3-224 |
| HMAC-SHA3-256 | `2.16.840.1.101.3.4.2.14` | id-hmacWithSHA3-256 |
| HMAC-SHA3-384 | `2.16.840.1.101.3.4.2.15` | id-hmacWithSHA3-384 |
| HMAC-SHA3-512 | `2.16.840.1.101.3.4.2.16` | id-hmacWithSHA3-512 |
| HMAC-GOST3411-2012-256 | `1.2.643.7.1.1.4.1` | id-tc26-hmac-gost-3411-12-256 |
| HMAC-GOST3411-2012-512 | `1.2.643.7.1.1.4.2` | id-tc26-hmac-gost-3411-12-512 |
| HMAC-RIPEMD160 | `1.3.6.1.5.5.8.1.4` | hmacRIPEMD160 |
| HMAC-TIGER | `1.3.6.1.5.5.8.1.3` | hmacTiger |

A lookup takes the number, not the OID's name, and printing an entry shows the name.

The tag is as long as the digest. HMAC over a weak digest such as MD5 needs that digest's
feature, which is off by default.
