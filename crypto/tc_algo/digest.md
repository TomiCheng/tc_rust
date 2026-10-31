# Digests

`tc_algo::digest` creates message digests by name, by OID or by `Algorithm`, after
Bouncy Castle's `DigestUtilities`. Every digest it creates is an `AnyDigest`.

## Enabling digests

Each digest has its own Cargo feature, listed in the [table](#algorithms) below.
The default features cover every digest except two kinds, which are opt-in:

- **Weak digests**: MD2, MD4, MD5, SHA-1, RIPEMD-128, RIPEMD-256 (no stronger than
  RIPEMD-128, only longer) and GOST R 34.11-94.
- **NONE**, which is not a hash. Keeping it out means a stray `"NONE"` cannot
  silently turn hashing off.

```toml
[dependencies]
# Add a weak digest for compatibility with old data
tc_algo = { version = "0.1", features = ["sha1"] }

# Or keep only what you use
tc_algo = { version = "0.1", default-features = false, features = ["sha256"] }
```

Family features enable every size of a digest at once, the weak ones included:
`md`, `sha`, `sha3`, `keccak`, `shake`, `blake2b`, `blake2s`, `dstu7564`,
`gost3411-2012` and `ripemd`.

## Usage

### In three steps

Get a digest, feed it, then finish. `finalize` returns the hash and resets the
digest for the next message.

```rust
use tc_algo::digest::{self, Algorithm};

let mut sha256 = digest::get(Algorithm::Sha256);
sha256.update(b"hello, ");
sha256.update(b"world");
let hash = sha256.finalize();
```

### In one step

```rust
use tc_algo::digest::{self, Algorithm};

let hash = digest::calculate(Algorithm::Sha256, b"hello, world");

// Into a buffer of your own: returns the length written, and panics if the
// buffer is shorter than the digest
let mut output = [0; 32];
let written = digest::calculate_into(Algorithm::Sha256, b"hello, world", &mut output);
```

### By name or OID

When the algorithm comes from configuration or from an ASN.1 `AlgorithmIdentifier`,
look it up instead of naming the variant. Names match without regard to ASCII case,
aliases are accepted, and a dotted OID string works wherever a name does.

```rust
use tc_algo::digest;
use tc_algo::{AlgoError, ErrorKind};

fn main() -> Result<(), AlgoError> {
    let mut sha256 = digest::get_by_name("sha-256")?;
    let same = digest::get_by_name("2.16.840.1.101.3.4.2.1")?;
    let hash = digest::calculate_by_name("SHA-256", b"hello, world")?;

    let error = digest::get_by_name("no-such-digest").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownDigest);
    Ok(())
}
```

`get_by_oid`, `calculate_by_oid` and `calculate_by_oid_into` take an `Asn1Oid`.
As in Bouncy Castle, some rows also answer to the HMAC OID built on the digest:
`id-hmacWithSHA256` finds SHA-256.

### Looking at the table

```rust
use tc_algo::digest::{self, Algorithm};

for entry in digest::algorithms() {
    println!("{entry}"); // e.g. `SHA-256  [id-sha256, id-hmacWithSHA256]`
}

let entry = Algorithm::Sha256.entry();
let name = entry.name(); // "SHA-256"
let oid = entry.oid(); // the digest's own OID, the one DigestInfo uses
```

### In generic code

`AnyDigest` implements `Digest` and `TryDigest`, which `tc_algo::digest` re-exports,
so it fits anywhere a `D: Digest` is expected, without a `tc_digest` dependency of
your own. It is also `Clone`, `Send` and `Sync`. Its `Debug` output shows only the
algorithm, never the digest's internal state, and its `Display` output is the
canonical name.

## Algorithms

Bits is the output length.

| `Algorithm` | Name | Aliases | Bits | Feature | Default | OID |
|---|---|---|---:|---|:---:|---|
| `Md2` | MD2 | | 128 | `md2` | | 1.2.840.113549.2.2 |
| `Md4` | MD4 | | 128 | `md4` | | 1.2.840.113549.2.4 |
| `Md5` | MD5 | | 128 | `md5` | | 1.2.840.113549.2.5 |
| `Sha1` | SHA-1 | SHA1 | 160 | `sha1` | | 1.3.14.3.2.26 |
| `Sha224` | SHA-224 | SHA224 | 224 | `sha224` | ✓ | 2.16.840.1.101.3.4.2.4 |
| `Sha256` | SHA-256 | SHA256 | 256 | `sha256` | ✓ | 2.16.840.1.101.3.4.2.1 |
| `Sha384` | SHA-384 | SHA384 | 384 | `sha384` | ✓ | 2.16.840.1.101.3.4.2.2 |
| `Sha512` | SHA-512 | SHA512 | 512 | `sha512` | ✓ | 2.16.840.1.101.3.4.2.3 |
| `Sha512_224` | SHA-512/224 | SHA512/224, SHA512-224, SHA512(224), SHA-512(224) | 224 | `sha512-224` | ✓ | 2.16.840.1.101.3.4.2.5 |
| `Sha512_256` | SHA-512/256 | SHA512/256, SHA512-256, SHA512(256), SHA-512(256) | 256 | `sha512-256` | ✓ | 2.16.840.1.101.3.4.2.6 |
| `Sha3_224` | SHA3-224 | | 224 | `sha3-224` | ✓ | 2.16.840.1.101.3.4.2.7 |
| `Sha3_256` | SHA3-256 | | 256 | `sha3-256` | ✓ | 2.16.840.1.101.3.4.2.8 |
| `Sha3_384` | SHA3-384 | | 384 | `sha3-384` | ✓ | 2.16.840.1.101.3.4.2.9 |
| `Sha3_512` | SHA3-512 | | 512 | `sha3-512` | ✓ | 2.16.840.1.101.3.4.2.10 |
| `Keccak224` | KECCAK-224 | KECCAK224 | 224 | `keccak-224` | ✓ | |
| `Keccak256` | KECCAK-256 | KECCAK256 | 256 | `keccak-256` | ✓ | |
| `Keccak288` | KECCAK-288 | KECCAK288 | 288 | `keccak-288` | ✓ | |
| `Keccak384` | KECCAK-384 | KECCAK384 | 384 | `keccak-384` | ✓ | |
| `Keccak512` | KECCAK-512 | KECCAK512 | 512 | `keccak-512` | ✓ | |
| `Shake128` | SHAKE128-256 | SHAKE128, SHAKE-128 | 256 | `shake128` | ✓ | 2.16.840.1.101.3.4.2.11 |
| `Shake256` | SHAKE256-512 | SHAKE256, SHAKE-256 | 512 | `shake256` | ✓ | 2.16.840.1.101.3.4.2.12 |
| `Blake2b160` | BLAKE2B-160 | | 160 | `blake2b-160` | ✓ | 1.3.6.1.4.1.1722.12.2.1.5 |
| `Blake2b256` | BLAKE2B-256 | | 256 | `blake2b-256` | ✓ | 1.3.6.1.4.1.1722.12.2.1.8 |
| `Blake2b384` | BLAKE2B-384 | | 384 | `blake2b-384` | ✓ | 1.3.6.1.4.1.1722.12.2.1.12 |
| `Blake2b512` | BLAKE2B-512 | | 512 | `blake2b-512` | ✓ | 1.3.6.1.4.1.1722.12.2.1.16 |
| `Blake2s128` | BLAKE2S-128 | | 128 | `blake2s-128` | ✓ | 1.3.6.1.4.1.1722.12.2.2.4 |
| `Blake2s160` | BLAKE2S-160 | | 160 | `blake2s-160` | ✓ | 1.3.6.1.4.1.1722.12.2.2.5 |
| `Blake2s224` | BLAKE2S-224 | | 224 | `blake2s-224` | ✓ | 1.3.6.1.4.1.1722.12.2.2.7 |
| `Blake2s256` | BLAKE2S-256 | | 256 | `blake2s-256` | ✓ | 1.3.6.1.4.1.1722.12.2.2.8 |
| `Blake3_256` | BLAKE3-256 | | 256 | `blake3-256` | ✓ | 1.3.6.1.4.1.1722.12.2.3.8 |
| `Dstu7564_256` | DSTU7564-256 | | 256 | `dstu7564-256` | ✓ | 1.2.804.2.1.1.1.1.2.2.1 |
| `Dstu7564_384` | DSTU7564-384 | | 384 | `dstu7564-384` | ✓ | 1.2.804.2.1.1.1.1.2.2.2 |
| `Dstu7564_512` | DSTU7564-512 | | 512 | `dstu7564-512` | ✓ | 1.2.804.2.1.1.1.1.2.2.3 |
| `Gost3411` | GOST3411 | | 256 | `gost3411` | | 1.2.643.2.2.9 |
| `Gost3411_2012_256` | GOST3411-2012-256 | | 256 | `gost3411-2012-256` | ✓ | 1.2.643.7.1.1.2.2 |
| `Gost3411_2012_512` | GOST3411-2012-512 | | 512 | `gost3411-2012-512` | ✓ | 1.2.643.7.1.1.2.3 |
| `Ripemd128` | RIPEMD128 | RIPEMD-128 | 128 | `ripemd128` | | 1.3.36.3.2.2 |
| `Ripemd160` | RIPEMD160 | RIPEMD-160 | 160 | `ripemd160` | ✓ | 1.3.36.3.2.1 |
| `Ripemd256` | RIPEMD256 | RIPEMD-256 | 256 | `ripemd256` | | 1.3.36.3.2.3 |
| `Ripemd320` | RIPEMD320 | RIPEMD-320 | 320 | `ripemd320` | ✓ | |
| `Sm3` | SM3 | | 256 | `sm3` | ✓ | 1.2.156.10197.1.401 |
| `Tiger` | TIGER | | 192 | `tiger` | ✓ | |
| `Whirlpool` | WHIRLPOOL | | 512 | `whirlpool` | ✓ | |
| `Null` | NONE | | — | `null-digest` | | |

The OID column shows each digest's own OID. The rows without one have none in
Bouncy Castle either.

### Notes

- **SHAKE** appears here as a fixed-length digest, as in Bouncy Castle: SHAKE128
  gives 256 bits and SHAKE256 gives 512.
- **Raw Keccak** is the version before SHA-3 was standardized, with different
  padding; Ethereum's Keccak-256 is this one. It has no OID.
- **GOST3411** is GOST R 34.11-94; **GOST3411-2012** is GOST R 34.11-2012
  (Streebog). **DSTU7564** is the Ukrainian Kupyna.
- **NONE** is not a hash: it passes the message through unchanged, for signers
  that sign the message as it is. Its size is the number of bytes it has taken,
  so it is 0 until the first `update`. The variant is `Algorithm::Null` so it does
  not read as `Option::None`.
