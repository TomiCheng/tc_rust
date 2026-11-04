# Digests

`tc_algo::digest` creates message digests by name or by OID. Every digest it creates is an
`AnyDigest`.

## Enabling digests

Nothing is on by default. Each digest has its own Cargo feature, listed in the
[table](#algorithms) below.

```toml
[dependencies]
tc_algo = { version = "0.1", features = ["sha256"] }
```

Family features enable every size of a digest at once, the weak ones included: `md`, `sha`,
`sha3`, `keccak`, `shake`, `blake2b`, `blake2s`, `dstu7564`, `gost3411-2012`, `ripemd`, `skein`
and `esch`.

## Usage

### In three steps

Get a digest, feed it, then finish. `finalize` returns the hash and resets the digest for the
next message.

```rust
use tc_algo::AlgoError;
use tc_algo::digest;

fn main() -> Result<(), AlgoError> {
    let mut sha256 = digest::get_by_name("SHA-256")?;
    sha256.update(b"hello, ");
    sha256.update(b"world");
    let hash = sha256.finalize();
    assert_eq!(hash.len(), 32);
    Ok(())
}
```

### In one step

```rust
use tc_algo::AlgoError;
use tc_algo::digest;

fn main() -> Result<(), AlgoError> {
    let hash = digest::calculate_by_name("SHA-256", b"hello, world")?;

    // Into a buffer of your own: returns the length written, and panics if the
    // buffer is shorter than the digest
    let mut output = [0; 32];
    let written = digest::calculate_by_name_into("SHA-256", b"hello, world", &mut output)?;
    assert_eq!(&output[..written], hash);
    Ok(())
}
```

### By name or OID

Names match without regard to ASCII case, aliases are accepted, and a dotted OID string works
wherever a name does.

```rust
use tc_algo::digest;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let sha256 = digest::get_by_name("sha256")?;
    assert_eq!(sha256.entry().name(), "SHA-256");

    let same = digest::get_by_name("2.16.840.1.101.3.4.2.1")?;
    assert_eq!(same.entry().name(), "SHA-256");

    let error = digest::get_by_name("no-such-digest").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownDigest);
    Ok(())
}
```

`get_by_oid`, `calculate_by_oid` and `calculate_by_oid_into` take an `Asn1Oid`. Some rows also
answer to the HMAC OID built on the digest: `id-hmacWithSHA256` finds SHA-256.

### Looking at the table

```rust
use tc_algo::digest;

for entry in digest::algorithms() {
    println!("{entry}"); // e.g. `SHA-256  [id-sha256, id-hmacWithSHA256]`
}
```

### In generic code

`AnyDigest` implements `Digest` and `TryDigest`, which `tc_algo::digest` re-exports,
so it fits anywhere a `D: Digest` is expected, without a `tc_digest` dependency of
your own. It is also `Clone`, `Send` and `Sync`. Its `Debug` output shows only the
name, never the digest's internal state, and its `Display` output is the canonical
name.

## Algorithms

| Name | OID | Feature | Bytes | Weak |
|---|---|---|---:|:---:|
| MD2 | `1.2.840.113549.2.2` | `md2` | 16 | ✓ |
| MD4 | `1.2.840.113549.2.4` | `md4` | 16 | ✓ |
| MD5 | `1.2.840.113549.2.5` | `md5` | 16 | ✓ |
| SHA-1 | `1.3.14.3.2.26` | `sha1` | 20 | ✓ |
| SHA-224 | `2.16.840.1.101.3.4.2.4` | `sha224` | 28 | |
| SHA-256 | `2.16.840.1.101.3.4.2.1` | `sha256` | 32 | |
| SHA-384 | `2.16.840.1.101.3.4.2.2` | `sha384` | 48 | |
| SHA-512 | `2.16.840.1.101.3.4.2.3` | `sha512` | 64 | |
| SHA-512/224 | `2.16.840.1.101.3.4.2.5` | `sha512-224` | 28 | |
| SHA-512/256 | `2.16.840.1.101.3.4.2.6` | `sha512-256` | 32 | |
| SHA3-224 | `2.16.840.1.101.3.4.2.7` | `sha3-224` | 28 | |
| SHA3-256 | `2.16.840.1.101.3.4.2.8` | `sha3-256` | 32 | |
| SHA3-384 | `2.16.840.1.101.3.4.2.9` | `sha3-384` | 48 | |
| SHA3-512 | `2.16.840.1.101.3.4.2.10` | `sha3-512` | 64 | |
| KECCAK-224 | — | `keccak-224` | 28 | |
| KECCAK-256 | — | `keccak-256` | 32 | |
| KECCAK-288 | — | `keccak-288` | 36 | |
| KECCAK-384 | — | `keccak-384` | 48 | |
| KECCAK-512 | — | `keccak-512` | 64 | |
| SHAKE128-256 | `2.16.840.1.101.3.4.2.11` | `shake128` | 32 | |
| SHAKE256-512 | `2.16.840.1.101.3.4.2.12` | `shake256` | 64 | |
| BLAKE2B-160 | `1.3.6.1.4.1.1722.12.2.1.5` | `blake2b-160` | 20 | |
| BLAKE2B-256 | `1.3.6.1.4.1.1722.12.2.1.8` | `blake2b-256` | 32 | |
| BLAKE2B-384 | `1.3.6.1.4.1.1722.12.2.1.12` | `blake2b-384` | 48 | |
| BLAKE2B-512 | `1.3.6.1.4.1.1722.12.2.1.16` | `blake2b-512` | 64 | |
| BLAKE2S-128 | `1.3.6.1.4.1.1722.12.2.2.4` | `blake2s-128` | 16 | |
| BLAKE2S-160 | `1.3.6.1.4.1.1722.12.2.2.5` | `blake2s-160` | 20 | |
| BLAKE2S-224 | `1.3.6.1.4.1.1722.12.2.2.7` | `blake2s-224` | 28 | |
| BLAKE2S-256 | `1.3.6.1.4.1.1722.12.2.2.8` | `blake2s-256` | 32 | |
| BLAKE3-256 | `1.3.6.1.4.1.1722.12.2.3.8` | `blake3-256` | 32 | |
| DSTU7564-256 | `1.2.804.2.1.1.1.1.2.2.1` | `dstu7564-256` | 32 | |
| DSTU7564-384 | `1.2.804.2.1.1.1.1.2.2.2` | `dstu7564-384` | 48 | |
| DSTU7564-512 | `1.2.804.2.1.1.1.1.2.2.3` | `dstu7564-512` | 64 | |
| GOST3411 | `1.2.643.2.2.9` | `gost3411` | 32 | ✓ |
| GOST3411-2012-256 | `1.2.643.7.1.1.2.2` | `gost3411-2012-256` | 32 | |
| GOST3411-2012-512 | `1.2.643.7.1.1.2.3` | `gost3411-2012-512` | 64 | |
| RIPEMD128 | `1.3.36.3.2.2` | `ripemd128` | 16 | ✓ |
| RIPEMD160 | `1.3.36.3.2.1` | `ripemd160` | 20 | |
| RIPEMD256 | `1.3.36.3.2.3` | `ripemd256` | 32 | ✓ |
| RIPEMD320 | — | `ripemd320` | 40 | |
| SM3 | `1.2.156.10197.1.401` | `sm3` | 32 | |
| TIGER | — | `tiger` | 24 | |
| WHIRLPOOL | — | `whirlpool` | 64 | |
| SKEIN-256-128 | — | `skein-256-128` | 16 | |
| SKEIN-256-160 | — | `skein-256-160` | 20 | |
| SKEIN-256-224 | — | `skein-256-224` | 28 | |
| SKEIN-256-256 | — | `skein-256-256` | 32 | |
| SKEIN-512-128 | — | `skein-512-128` | 16 | |
| SKEIN-512-160 | — | `skein-512-160` | 20 | |
| SKEIN-512-224 | — | `skein-512-224` | 28 | |
| SKEIN-512-256 | — | `skein-512-256` | 32 | |
| SKEIN-512-384 | — | `skein-512-384` | 48 | |
| SKEIN-512-512 | — | `skein-512-512` | 64 | |
| SKEIN-1024-384 | — | `skein-1024-384` | 48 | |
| SKEIN-1024-512 | — | `skein-1024-512` | 64 | |
| SKEIN-1024-1024 | — | `skein-1024-1024` | 128 | |
| ESCH-256 | — | `esch-256` | 32 | |
| ESCH-384 | — | `esch-384` | 48 | |
| XOODYAK | — | `xoodyak` | 32 | |
| PHOTON-BEETLE | — | `photon-beetle` | 32 | |
| ASCON-HASH256 | — | `ascon-hash256` | 32 | |
| ASCON-HASH | — | `ascon-hash-legacy` | 32 | |
| ASCON-HASHA | — | `ascon-hash-legacy` | 32 | |
| ISAP | — | `isap` | 32 | |
| HARAKA-256 | — | `haraka` | 32 | |
| HARAKA-512 | — | `haraka` | 32 | |
| NONE | — | `null-digest` | — | |

Bytes is the length of the hash. The OID is the digest's own, and a row with `—` has none. Weak marks a
digest that is broken or no stronger than one that is, for old data only.

### Notes

- **SHAKE** appears here as a fixed-length digest: SHAKE128 gives 32 bytes and SHAKE256 64.
- **Raw Keccak** is the version before SHA-3 was standardized, with different padding;
  Ethereum's Keccak-256 is this one.
- **GOST3411** is GOST R 34.11-94; **GOST3411-2012** is GOST R 34.11-2012 (Streebog).
  **DSTU7564** is the Ukrainian Kupyna.
- **ASCON-HASH** and **ASCON-HASHA** are from before NIST standardized Ascon, for old data.
  New designs want ASCON-HASH256.
- **Haraka** takes an input of exactly 32 bytes for HARAKA-256 and 64 for HARAKA-512, and panics
  on any other length: use it only where the length is fixed by design.
- **NONE** is not a hash: it passes the message through unchanged, for signers that sign the
  message as it is. Its size is the number of bytes it has taken, so it is 0 until the first
  `update`.
