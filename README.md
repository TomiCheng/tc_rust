# tc_rust

A pure-Rust cryptography workspace, ported from the
[Bouncy Castle C#](https://github.com/bcgit/bc-csharp) library **as a personal
learning project** for studying Rust and cryptographic algorithms.

> **Disclaimer.** This is an independent, unofficial re-implementation. It is
> **not** affiliated with, endorsed by, or connected to the Legion of the
> Bouncy Castle Inc. "Bouncy Castle" is used only to credit the reference
> design the algorithms are based on.

## Status

Early / work in progress. APIs are unstable and may change. Not audited — **do
not use in production or for real-world security.**

## Crates

| Crate | Description |
| --- | --- |
| [`tc_crypto_core`](crates/tc_crypto_core) | Shared cryptographic traits, currently including `TryDigest` / `Digest`. |
| [`tc_digest`](crates/tc_digest) | Message-digest algorithms ported from bc-csharp. |
| [`tc_math`](crates/tc_math) | Arbitrary-precision integers and number theory (`BigInteger`). |

### `tc_digest` status

Implemented algorithms include BLAKE2b/BLAKE2s, MD2/4/5, SHA-1/2/3, Keccak, RIPEMD,
Tiger, Whirlpool, SM3, GOST 34.11-2012, and DSTU 7564. See the
[`tc_digest` roadmap](crates/tc_digest/README.md) for the full list and test
coverage.

GOST 34.11-94 (`Gost3411Digest`) is intentionally deferred: the bc-csharp
implementation depends on `IBlockCipher` and `Gost28147Engine`, while this
workspace does not yet have a block-cipher abstraction or a GOST 28147 engine.
Those components will be introduced before porting the digest.

### `tc_math` highlights

- `BigInteger`: arbitrary-precision signed integer
  - Arithmetic, bitwise, and shift operators
  - Conversions: integer types, big-endian bytes, and strings (arbitrary radix)
  - Number theory: `gcd`, `mod_inverse`, and `mod_pow`
    (Barrett reduction + sliding-window, Montgomery for odd moduli)
  - Primality: `is_probable_prime`, `probable_prime`, `next_probable_prime`
    (Montgomery-domain Miller–Rabin + small-prime trial division)
- `no_std + alloc` support (enable via `--no-default-features`); the default
  `std` feature adds lazy caching.
- RNG is supplied by the caller through [`rand_core`](https://crates.io/crates/rand_core)
  0.10 (`&mut dyn Rng`), so entropy is never sourced internally.

## Building & testing

```bash
# complete workspace
cargo test --workspace

# individual crates
cargo test -p tc_digest
cargo test -p tc_math

# no_std + alloc
cargo build -p tc_digest --no-default-features
cargo build -p tc_math --no-default-features

# benchmarks
cargo bench -p tc_digest --bench blake2b
cargo bench -p tc_digest --bench blake2b --no-default-features
cargo bench -p tc_digest --bench blake2s
cargo bench -p tc_digest --bench blake2s --no-default-features
cargo bench -p tc_math
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option (SPDX: `MIT OR Apache-2.0`).
