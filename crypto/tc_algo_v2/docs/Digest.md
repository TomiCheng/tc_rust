# Digest

`algo.digest()` gives message digests by name or by OID. The `sha256` feature has the row.

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

| Name | Aliases | OIDs | Feature |
|---|---|---|---|
| `SHA-256` | `SHA256` | 2.16.840.1.101.3.4.2.1, 1.2.840.113549.2.9 | `sha256` |

## Using it

- `calculate_by_name` and `calculate_by_oid` hash a whole message at once.
- `get_by_name` and `get_by_oid` give a `Digest` to feed in parts with `update` or
  `update_byte`.
- `finalize` gives the hash and resets the digest; `do_final` writes it into a buffer of
  `digest_size` bytes. `reset` drops what was fed.
- `byte_length` is the size of the block the digest works on, as HMAC needs.
- `algorithms` lists the rows turned on. A name or OID not turned on is an error.
