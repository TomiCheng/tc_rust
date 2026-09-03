# tc_gmac

`tc_gmac` implements GMAC, the authentication-only specialization of GCM,
over a caller-selected 16-byte block cipher.

- Input supplied through `Mac::update` is authenticated as GCM AAD.
- Tags may contain 4 through 16 bytes; 12 bytes or more is recommended for
  general use.
- `MacInit<P>` accepts any `P` implementing `KeyParams + IvParams`, including
  `tc_params::KeyWithIvRef` and caller-owned parameter types.
- The nonce must be unique for every message authenticated with a given key.
- After `do_final`, initialize with a fresh nonce before the next message.
- The default `alloc` feature comes from `tc_gcm`'s nonce-reuse guard; `std` is
  not required.

Run its NIST CAVP tests from the workspace root:

```bash
cargo test -p tc_gmac --locked
```
