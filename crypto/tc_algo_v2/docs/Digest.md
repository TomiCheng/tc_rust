# Digest

`algo.digest()` gives message digests by name or by OID: SHA-1 and the SHA-2 family.

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

The OIDs after the first of each row are those of HMAC with the digest (and, for SHA-1, the
IPsec one), which Bouncy Castle also maps to the digest; they find the digest but are not its
OID. SHA-1 is broken for collisions and is here for old data only.

## Using it

- `calculate_by_name` and `calculate_by_oid` hash a whole message at once.
- `get_by_name` and `get_by_oid` give a `Digest` to feed in parts with `update` or
  `update_byte`.
- `finalize` gives the hash and resets the digest; `do_final` writes it into a buffer of
  `digest_size` bytes. `reset` drops what was fed.
- `byte_length` is the size of the block the digest works on, as HMAC needs.
- `algorithms` lists the rows turned on. A name or OID not turned on is an error.
