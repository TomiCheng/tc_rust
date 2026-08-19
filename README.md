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
| [`tc_math`](crates/tc_math) | Arbitrary-precision integers and number theory (`BigInteger`). |

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
# default (std)
cargo test -p tc_math

# no_std + alloc
cargo build -p tc_math --no-default-features

# benchmarks (mod_pow)
cargo bench -p tc_math
```

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE)
at your option (SPDX: `MIT OR Apache-2.0`).
