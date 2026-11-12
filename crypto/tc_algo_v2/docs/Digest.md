# Digest

`algo.digest()` gives message digests by name or by OID: SHA-1 and SHA-2, MD2, MD4 and MD5,
BLAKE2 and BLAKE3, RIPEMD, SM3, GOST R 34.11, DSTU 7564, Tiger, Whirlpool, and `NONE`.

```rust
use tc_algo_v2::{AlgoBuilder, DefaultAlgoBuilder};

let algo = DefaultAlgoBuilder::default().build();

// At once
let hash = algo.digest().calculate_by_name("SHA-256", b"abc")?;

// In parts
let mut digest = algo.digest().get_by_name("SHA-256")?;
digest.update(b"a");
digest.update(b"bc");
assert_eq!(digest.finalize(), hash);
```

## Algorithms

| Name | Aliases | OIDs | Feature | Note |
|---|---|---|---|---|
| `SHA-1` | `SHA1` | `1.3.14.3.2.26`, `1.2.840.113549.2.7`, `1.3.6.1.5.5.8.1.2` | `sha1` | weak |
| `SHA-224` | `SHA224` | `2.16.840.1.101.3.4.2.4`, `1.2.840.113549.2.8` | `sha224` |  |
| `SHA-256` | `SHA256` | `2.16.840.1.101.3.4.2.1`, `1.2.840.113549.2.9` | `sha256` |  |
| `SHA-384` | `SHA384` | `2.16.840.1.101.3.4.2.2`, `1.2.840.113549.2.10` | `sha384` |  |
| `SHA-512` | `SHA512` | `2.16.840.1.101.3.4.2.3`, `1.2.840.113549.2.11` | `sha512` |  |
| `SHA-512/224` | `SHA512/224`, `SHA512-224`, `SHA512(224)`, `SHA-512(224)` | `2.16.840.1.101.3.4.2.5`, `1.2.840.113549.2.12` | `sha512-224` |  |
| `SHA-512/256` | `SHA512/256`, `SHA512-256`, `SHA512(256)`, `SHA-512(256)` | `2.16.840.1.101.3.4.2.6`, `1.2.840.113549.2.13` | `sha512-256` |  |
| `MD2` |  | `1.2.840.113549.2.2` | `md2` | weak, variable time |
| `MD4` |  | `1.2.840.113549.2.4` | `md4` | weak |
| `MD5` |  | `1.2.840.113549.2.5` | `md5` | weak |
| `BLAKE2B-160` |  | `1.3.6.1.4.1.1722.12.2.1.5` | `blake2b-160` |  |
| `BLAKE2B-256` |  | `1.3.6.1.4.1.1722.12.2.1.8` | `blake2b-256` |  |
| `BLAKE2B-384` |  | `1.3.6.1.4.1.1722.12.2.1.12` | `blake2b-384` |  |
| `BLAKE2B-512` |  | `1.3.6.1.4.1.1722.12.2.1.16` | `blake2b-512` |  |
| `BLAKE2S-128` |  | `1.3.6.1.4.1.1722.12.2.2.4` | `blake2s-128` |  |
| `BLAKE2S-160` |  | `1.3.6.1.4.1.1722.12.2.2.5` | `blake2s-160` |  |
| `BLAKE2S-224` |  | `1.3.6.1.4.1.1722.12.2.2.7` | `blake2s-224` |  |
| `BLAKE2S-256` |  | `1.3.6.1.4.1.1722.12.2.2.8` | `blake2s-256` |  |
| `BLAKE3-256` |  | `1.3.6.1.4.1.1722.12.2.3.8` | `blake3-256` |  |
| `RIPEMD128` | `RIPEMD-128` | `1.3.36.3.2.2` | `ripemd128` |  |
| `RIPEMD160` | `RIPEMD-160` | `1.3.36.3.2.1` | `ripemd160` |  |
| `RIPEMD256` | `RIPEMD-256` | `1.3.36.3.2.3` | `ripemd256` |  |
| `RIPEMD320` | `RIPEMD-320` |  | `ripemd320` |  |
| `SM3` |  | `1.2.156.10197.1.401` | `sm3` |  |
| `GOST3411` |  | `1.2.643.2.2.9` | `gost3411` | variable time |
| `GOST3411-2012-256` |  | `1.2.643.7.1.1.2.2` | `gost3411-2012-256` | variable time |
| `GOST3411-2012-512` |  | `1.2.643.7.1.1.2.3` | `gost3411-2012-512` | variable time |
| `DSTU7564-256` |  | `1.2.804.2.1.1.1.1.2.2.1` | `dstu7564-256` | variable time |
| `DSTU7564-384` |  | `1.2.804.2.1.1.1.1.2.2.2` | `dstu7564-384` | variable time |
| `DSTU7564-512` |  | `1.2.804.2.1.1.1.1.2.2.3` | `dstu7564-512` | variable time |
| `TIGER` |  |  | `tiger` | variable time |
| `WHIRLPOOL` |  |  | `whirlpool` | variable time |
| `NONE` |  |  | `null-digest` | not a hash |

The OIDs after the first of each row are those of HMAC with the digest (and, for SHA-1, the
IPsec one), which Bouncy Castle also maps to the digest; they find the digest but are not its
OID. A weak digest is broken for collisions and is here for old data only. A variable-time
digest looks up tables by the message, so it can leak the message through cache timing: hash
only public data with it.

`NONE` is Bouncy Castle's `NullDigest`: it gives back what it was fed, for a signer given a
digest computed elsewhere. Its size is the length fed so far.

## Using it

- `calculate_by_name` and `calculate_by_oid` hash a whole message at once.
- `get_by_name` and `get_by_oid` give a `Digest` to feed in parts with `update` or
  `update_byte`.
- `finalize` gives the hash and resets the digest; `do_final` writes it into a buffer of
  `digest_size` bytes. `reset` drops what was fed.
- `byte_length` is the size of the block the digest works on, as HMAC needs.
- `algorithms` lists the rows turned on. A name or OID not turned on is an error.
