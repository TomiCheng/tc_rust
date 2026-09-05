# tc_prime developer guide

`tc_prime` is the workspace port of Bouncy Castle C#'s FIPS 186-4 prime
utilities. Its behavioral reference is:

```text
D:\github\bc-csharp\crypto\src\math\Primes.cs
D:\github\bc-csharp\crypto\test\src\math\test\PrimesTest.cs
```

This crate intentionally does not replace the general-purpose probable-prime
implementation in `tc_bigint`. The two layers have different responsibilities:

- `tc_bigint` owns inherent integer methods such as `is_probable_prime`,
  `probable_prime`, and `next_probable_prime`.
- `tc_prime` owns the FIPS helper routines used by higher-level RSA and DSA key
  generation and validation code.

`tc_prime` currently has no dependency on `tc_rsa`, and RSA key generation is
not wired to this crate yet.

## Module layout

| Module | Responsibility | Bouncy Castle counterpart |
| --- | --- | --- |
| `integer.rs` | `PrimeInteger` trait bundle and shared conversions | Generic Rust integration layer |
| `small_factors.rs` | Packed trial division through prime 211 | `HasAnySmallFactors` / `ImplHasAnySmallFactors` |
| `miller_rabin.rs` | Random-base and fixed-base Miller-Rabin | `IsMRProbablePrime*` |
| `enhanced.rs` | Miller-Rabin with factor recovery | `EnhancedMRProbablePrimeTest` / `MROutput` |
| `shawe_taylor.rs` | Recursive provable-prime generation | `GenerateSTRandomPrime` / `STOutput` |
| `error.rs` | Checked Rust error reporting | BC argument and operation exceptions |

Keep unit tests inline with their owning module. This crate does not use a
top-level `tests/` directory so private helpers can be verified directly.

## Features and dependency boundaries

| Feature | Default | Effect |
| --- | ---: | --- |
| `alloc` | yes | Enables `tc_bigint::BigUint` support through the dependency's `alloc` feature |
| `digest` | no | Enables Shawe-Taylor generation and depends on `tc_digest`; also enables `alloc` |

With default features disabled, the crate is `no_std`, does not allocate, and
continues to support `FixedBigUint<N>`. `rand_core` is always enabled because
the Miller-Rabin functions receive their random source from the caller.

The dependency direction must remain:

```text
tc_prime -> tc_bigint
tc_prime --digest feature--> tc_digest
```

Do not add a reverse dependency from `tc_bigint`, and do not move
Shawe-Taylor into the math-only integer crate. Digest implementations such as
`tc_sha` and `rand` are development dependencies used for tests and doctests
only.

## Porting invariants

### Generic integer operations

Public algorithms are generic over `PrimeInteger`. Both `BigUint` and
`FixedBigUint<N>` satisfy the bundle through a blanket implementation. Avoid
adding borrowed-left-hand-side HRTB requirements to the bundle; clone an owned
left operand where an operator requires one.

Fixed-width overflow must be returned as `PrimeError::Overflow`. It must not be
allowed to panic or silently truncate.

### Modular squaring

Never port BC's following expression literally:

```text
z = z.Square().Mod(w)
```

`FixedBigUint<N>::square` cannot hold a full-width square and may overflow
before reduction. Miller-Rabin loops must use:

```rust,ignore
z = z.mod_mul(&z, modulus);
```

The initial exponentiation uses `ModPow`. `MontyForm<BigUint>` and
`FixedMontyForm<N>` are intentionally separate concrete types and do not have
a shared generic contract beyond retrieval, so `tc_prime` must not attempt to
name either form in its generic API.

### Packed trial division

The ten packed moduli must continue to cover every prime from 2 through 211.
Each packed group performs one big-integer remainder; divisibility within the
group is then checked using `u32` arithmetic.

The semantics deliberately match Bouncy Castle: a candidate which is itself a
small prime counts as having a small factor. For example,
`has_any_small_factors(3)` is `true`. Do not reuse the differently shaped
internal helper from `tc_bigint` without preserving this behavior.

### Shawe-Taylor compatibility

Shawe-Taylor output is deterministic. Preserve all seed increments, including
the increments performed when packed trial division rejects a candidate. A
change to seed advancement changes the generated prime, final seed, and
counter even when the resulting number is still prime.

`HashGen` interprets digest output as an unsigned big-endian integer through
`ArrayEncoding`. Conversion failure for a narrow fixed-width target maps to
`PrimeError::Overflow`.

The `IsPrime32` overflow guard must remain ordered as follows:

```rust,ignore
(base >> 16 != 0) || (base * base >= candidate)
```

The left side prevents the multiplication on the right from overflowing.

### Randomness and timing

The APIs accept `rand_core::Rng` so deterministic test generators and caller
selected RNGs remain possible. Production key generation must supply a source
which also implements `rand_core::CryptoRng` and is securely seeded.

These routines are variable-time. Candidates and trial bases are expected to
be public for the purpose of primality testing. Do not add `_ct` naming unless
the complete implementation has actually been hardened and reviewed for
constant-time behavior.

## Test coverage

The tests are expected to cover both `BigUint` and a fixed-width integer where
the feature set permits it. Keep the following cases when changing an
algorithm:

- every integer multiplier from 2 through 211 for packed trial division;
- known primes, Carmichael numbers, and strong pseudoprimes for Miller-Rabin;
- prime squares, products of distinct primes, and even candidates for enhanced
  Miller-Rabin;
- deterministic SHA-1 and SHA-256 Shawe-Taylor output, changed-seed behavior,
  independent probable-prime verification, and fixed-width overflow;
- the `ModMul` path for fixed-width Miller-Rabin, which must not overflow.

Tests and doctests use a reproducibly seeded `rand::rngs::StdRng`. Production
callers remain responsible for constructing and seeding their own RNG.

## Verification

Run the crate under every supported feature configuration:

```bash
cargo test -p tc_prime
cargo test -p tc_prime --all-features
cargo test -p tc_prime --no-default-features
cargo test -p tc_prime --no-default-features --features digest
cargo build -p tc_prime --no-default-features
```

Then run lint, formatting, documentation, and workspace checks:

```bash
cargo clippy -p tc_prime --all-features --all-targets -- -D warnings
cargo fmt -p tc_prime --check
cargo test -p tc_prime --doc --all-features
cargo doc -p tc_prime --all-features --no-deps
cargo test --workspace
```

## Out of scope

- Do not change `tc_bigint/src/prime/` as part of work on this crate.
- Do not wire `tc_rsa` key generation without a separate design and change.
- Do not claim constant-time behavior.
