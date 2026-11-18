# Digest

`algo.digest()` gives message digests by name or by OID: SHA-1, SHA-2 and SHA-3, Keccak, SHAKE
at a fixed size, MD2, MD4 and MD5, BLAKE2 and BLAKE3, RIPEMD, SM3, GOST R 34.11, DSTU 7564,
Tiger, Whirlpool, Ascon, Skein, Haraka, PHOTON-Beetle, ESCH, Xoodyak, and `NONE`.

```rust
use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};

let algo = DefaultAlgoBuilder::default().build();

// At once
let hash = algo.digest().calculate_by_name("SHA-256", b"abc")?;

// In parts
let mut digest = algo.digest().get_by_name("SHA-256")?;
digest.try_update(b"a")?;
digest.try_update(b"bc")?;
assert_eq!(digest.finalize()?, hash);
```

## Algorithms

| Name | Aliases | OIDs | Feature | Note |
|---|---|---|---|---|
| `SHA-1` | `SHA1` | `1.3.14.3.2.26`, `1.2.840.113549.2.7`, `1.3.6.1.5.5.8.1.2` | `sha` | weak |
| `SHA-224` | `SHA224` | `2.16.840.1.101.3.4.2.4`, `1.2.840.113549.2.8` | `sha` |  |
| `SHA-256` | `SHA256` | `2.16.840.1.101.3.4.2.1`, `1.2.840.113549.2.9` | `sha` |  |
| `SHA-384` | `SHA384` | `2.16.840.1.101.3.4.2.2`, `1.2.840.113549.2.10` | `sha` |  |
| `SHA-512` | `SHA512` | `2.16.840.1.101.3.4.2.3`, `1.2.840.113549.2.11` | `sha` |  |
| `SHA-512/224` | `SHA512/224`, `SHA512-224`, `SHA512(224)`, `SHA-512(224)` | `2.16.840.1.101.3.4.2.5`, `1.2.840.113549.2.12` | `sha` |  |
| `SHA-512/256` | `SHA512/256`, `SHA512-256`, `SHA512(256)`, `SHA-512(256)` | `2.16.840.1.101.3.4.2.6`, `1.2.840.113549.2.13` | `sha` |  |
| `KECCAK-224` | `KECCAK224` |  | `keccak` |  |
| `KECCAK-256` | `KECCAK256` |  | `keccak` |  |
| `KECCAK-288` | `KECCAK288` |  | `keccak` |  |
| `KECCAK-384` | `KECCAK384` |  | `keccak` |  |
| `KECCAK-512` | `KECCAK512` |  | `keccak` |  |
| `SHA3-224` |  | `2.16.840.1.101.3.4.2.7`, `2.16.840.1.101.3.4.2.13` | `keccak` |  |
| `SHA3-256` |  | `2.16.840.1.101.3.4.2.8`, `2.16.840.1.101.3.4.2.14` | `keccak` |  |
| `SHA3-384` |  | `2.16.840.1.101.3.4.2.9`, `2.16.840.1.101.3.4.2.15` | `keccak` |  |
| `SHA3-512` |  | `2.16.840.1.101.3.4.2.10`, `2.16.840.1.101.3.4.2.16` | `keccak` |  |
| `SHAKE128-256` | `SHAKE128`, `SHAKE-128` | `2.16.840.1.101.3.4.2.11` | `keccak` |  |
| `SHAKE256-512` | `SHAKE256`, `SHAKE-256` | `2.16.840.1.101.3.4.2.12` | `keccak` |  |
| `MD2` |  | `1.2.840.113549.2.2` | `md` | weak, variable time |
| `MD4` |  | `1.2.840.113549.2.4` | `md` | weak |
| `MD5` |  | `1.2.840.113549.2.5` | `md` | weak |
| `BLAKE2B-160` |  | `1.3.6.1.4.1.1722.12.2.1.5` | `blake` |  |
| `BLAKE2B-256` |  | `1.3.6.1.4.1.1722.12.2.1.8` | `blake` |  |
| `BLAKE2B-384` |  | `1.3.6.1.4.1.1722.12.2.1.12` | `blake` |  |
| `BLAKE2B-512` |  | `1.3.6.1.4.1.1722.12.2.1.16` | `blake` |  |
| `BLAKE2S-128` |  | `1.3.6.1.4.1.1722.12.2.2.4` | `blake` |  |
| `BLAKE2S-160` |  | `1.3.6.1.4.1.1722.12.2.2.5` | `blake` |  |
| `BLAKE2S-224` |  | `1.3.6.1.4.1.1722.12.2.2.7` | `blake` |  |
| `BLAKE2S-256` |  | `1.3.6.1.4.1.1722.12.2.2.8` | `blake` |  |
| `BLAKE3-256` |  | `1.3.6.1.4.1.1722.12.2.3.8` | `blake` |  |
| `RIPEMD128` | `RIPEMD-128` | `1.3.36.3.2.2` | `ripemd` |  |
| `RIPEMD160` | `RIPEMD-160` | `1.3.36.3.2.1` | `ripemd` |  |
| `RIPEMD256` | `RIPEMD-256` | `1.3.36.3.2.3` | `ripemd` |  |
| `RIPEMD320` | `RIPEMD-320` |  | `ripemd` |  |
| `SM3` |  | `1.2.156.10197.1.401` | `sm3` |  |
| `GOST3411` |  | `1.2.643.2.2.9` | `gost3411` | variable time |
| `GOST3411-2012-256` |  | `1.2.643.7.1.1.2.2` | `gost3411` | variable time |
| `GOST3411-2012-512` |  | `1.2.643.7.1.1.2.3` | `gost3411` | variable time |
| `DSTU7564-256` |  | `1.2.804.2.1.1.1.1.2.2.1` | `dstu7564` | variable time |
| `DSTU7564-384` |  | `1.2.804.2.1.1.1.1.2.2.2` | `dstu7564` | variable time |
| `DSTU7564-512` |  | `1.2.804.2.1.1.1.1.2.2.3` | `dstu7564` | variable time |
| `TIGER` |  |  | `misc-digest` | variable time |
| `WHIRLPOOL` |  |  | `misc-digest` | variable time |
| `ASCON-HASH256` |  |  | `ascon-hash` |  |
| `ASCON-HASH` |  |  | `ascon-hash` | pre-standard |
| `ASCON-HASHA` |  |  | `ascon-hash` | pre-standard |
| `ISAP` |  |  | `ascon-hash` | pre-standard |
| `SKEIN-256-128` |  |  | `skein` |  |
| `SKEIN-256-160` |  |  | `skein` |  |
| `SKEIN-256-224` |  |  | `skein` |  |
| `SKEIN-256-256` |  |  | `skein` |  |
| `SKEIN-512-128` |  |  | `skein` |  |
| `SKEIN-512-160` |  |  | `skein` |  |
| `SKEIN-512-224` |  |  | `skein` |  |
| `SKEIN-512-256` |  |  | `skein` |  |
| `SKEIN-512-384` |  |  | `skein` |  |
| `SKEIN-512-512` |  |  | `skein` |  |
| `SKEIN-1024-384` |  |  | `skein` |  |
| `SKEIN-1024-512` |  |  | `skein` |  |
| `SKEIN-1024-1024` |  |  | `skein` |  |
| `HARAKA-256` |  |  | `misc-digest` | fixed input, variable time without AES-NI |
| `HARAKA-512` |  |  | `misc-digest` | fixed input, variable time without AES-NI |
| `PHOTON-BEETLE` |  |  | `misc-digest` | variable time |
| `ESCH-256` |  |  | `misc-digest` |  |
| `ESCH-384` |  |  | `misc-digest` |  |
| `XOODYAK` |  |  | `misc-digest` |  |
| `NONE` |  |  | always on | not a hash |

The OIDs after the first of each row are those of HMAC with the digest (and, for SHA-1, the
IPsec one), which Bouncy Castle also maps to the digest; they find the digest but are not its
OID. A weak digest is broken for collisions and is here for old data only. A variable-time
digest looks up tables by the message, so it can leak the message through cache timing: hash
only public data with it.

Bouncy Castle's `DigestUtilities` has no row from `ASCON-HASH256` to `XOODYAK`; they are here
by the names of their digests, with no alias or OID. A pre-standard digest is the Ascon of
before NIST's SP 800-232, for old data only. Haraka takes exactly 32 or 64 bytes: an input of
another length is `DataLength` from `try_do_final`.

`SHAKE128-256` and `SHAKE256-512` are SHAKE cut to 256 and 512 bits, as Bouncy Castle gives
them; `SHAKE256` here is that digest, not the XOF of `algo.xof()`, which gives any length.

`NONE` is Bouncy Castle's `NullDigest`: it gives back what it was fed, for a signer given a
digest computed elsewhere. Its size is the length fed so far.

## Using it

- `calculate_by_name` and `calculate_by_oid` hash a whole message at once.
- `get_by_name` and `get_by_oid` give a `Digest`, which is a `TryDigest` of `tc_digest` with
  `AlgoError` for its errors, so code written for `TryDigest` takes it as it is. Feed it in parts
  with `try_update` or `try_update_byte`.
- `finalize` gives the hash and starts the next message; `try_do_final` writes it into a buffer of
  `digest_size` bytes. `try_reset` drops what was fed. An output shorter than the hash is
  `DataLength`, and the message stays in place.
- `byte_length` is the size of the block the digest works on, as HMAC needs.
- `algorithms` lists the rows turned on. A name or OID not turned on is an error.
