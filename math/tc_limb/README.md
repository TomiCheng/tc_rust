# tc_limb

Fixed-width, little-endian limb arithmetic. This crate uses `#![no_std]` with
no `alloc`, heap allocation, or `unsafe`. Its only runtime dependency is
`tc_constant_time`; `num-bigint` is used solely as a test oracle. It has no
runtime or development dependency on `tc_bigint`.

The fixed-width integers in `tc_bigint` share this crate's `LimbArray` storage
and unsigned primitives. Signed interpretation and variable-length integers
remain the responsibility of `tc_bigint`; this crate does not depend on it.

## Storage model

`Limb` wraps a private `Word`. Construct it with `Limb::new(word)` and retrieve
its value with `to_word()`.

| Target pointer width | `Word` | `WideWord` |
| --- | --- | --- |
| 64-bit | `u64` | `u128` |
| 16-bit, 32-bit | `u32` | `u64` |

Word widths follow the existing `tc_bigint` configuration, so each limb is
32 bits on i686. `N` counts limbs, not bits; the fixed bit width is
`N * Word::BITS`. Callers must explicitly define portable serialization formats
rather than assume that memory layout and word width are identical across targets.

`LimbArray<const N: usize>` provides unsigned fixed-width storage and arithmetic
primitives. Its highest bit is not a sign bit. Signed interpretation, including
`abs` and `is_negative`, belongs to the higher-level `FixedBigInt` type. The
private field is `[Limb; N]`, with index zero holding the least significant word.
Use `new`, `zero`, `as_limbs`, and `into_limbs` to construct or access the
fixed-length storage. Values with different `N` cannot be combined
in arithmetic operations; there is no implicit zero extension or truncation.

```rust
use tc_limb::{Limb, LimbArray, Word};

let max = LimbArray::new([Limb::new(Word::MAX); 2]);
let one = LimbArray::new([Limb::new(1), Limb::new(0)]);
let (sum, carry) = max.add(&one);
assert!(sum.is_zero());
assert!(carry);

let (low, high) = max.mul_wide(&one);
assert_eq!(low, max);
assert!(high.is_zero());
```

## Single-limb semantics

| Operation | Result and constraints |
| --- | --- |
| `carrying_add` | Low word and carry word of `self + rhs + carry`; the input carry may be any word, and the output carry may exceed one |
| `borrowing_sub` | Low word and borrow bit of `self - rhs - borrow`; the input borrow must be zero or one |
| `overflowing_add`, `overflowing_sub` | Truncated result and overflow/borrow flag |
| `wrapping_add`, `wrapping_sub`, `wrapping_neg` | Result modulo `2^Word::BITS` |
| `widening_mul` | Low and high words of the full product |
| `+`, `+=`, `-`, `-=`, `*` | Always panic on arithmetic overflow, in both debug and release builds |
| `&`, `\|`, `^`, `!` | Bitwise operations on the entire word |
| `<< usize`, `>> usize` | Logical shifts; the count must be less than `Word::BITS`, and bits shifted out to the left are discarded |

## Fixed-width methods

Both operands of binary operations and each half of double-width operations
use the same `LimbArray<N>` type.

| Method | Semantics |
| --- | --- |
| `cmp`, `Ord`, `PartialOrd` | Unsigned numeric ordering, starting at the highest limb |
| `add`, `sub` | Result modulo the fixed width, with the final carry/borrow flag |
| `mul` | Low half of the product and a flag indicating whether the high half is nonzero |
| `mul_wide`, `square_wide` | Full product/square as `(low, high)` |
| `mul_add_to` | Adds the product to mutable low and high accumulators; returns overflow beyond double width |
| `div_rem` | Unsigned quotient and remainder; panics on a zero divisor |
| `wide_rem` | Remainder modulo `modulus`, with `self` as the low half and `high` as the high half; panics on a zero modulus |
| `wrapping_neg` | Additive inverse modulo `2^(N * Word::BITS)`, without signed interpretation |
| `gcd` | Unsigned greatest common divisor, with `gcd(0, 0) = 0` |
| `bit_len` | Number of significant bits; zero for zero |
| `test_bit`, `set_bit`, `clear_bit`, `flip_bit` | Reads or returns a copy with a bit changed at a valid index; panics outside the fixed width |
| `is_zero`, `is_one` | Tests for zero/one |
| `shr_one` | Logical right shift by one bit in place, discarding the lowest bit |
| `shl_one` | Left shift by one bit in place, returning the highest bit shifted out |

A double-width result represents `low + high * 2^(N * Word::BITS)`. Each half
uses `[Limb; N]`, avoiding the generally unavailable `[Limb; 2 * N]` type-level
expression and temporary vector allocation.

`N = 0` is a valid zero-width value: ordinary arithmetic results are zero,
carry/borrow/multiplication overflow flags are false, `is_zero` is true, and
`is_one` is false. `div_rem` and `wide_rem` necessarily encounter a zero divisor
and panic; `test_bit` has no valid index.

## Constant-time scope

`Limb` and `LimbArray<N>` implement `ConditionallySelectable` and `ConstantTimeEq`
from `tc_constant_time`, and this crate re-exports those traits. Selection does
not branch on the choice bit or input values; equality reads every limb without
early exit. These guarantees concern values; the public array length `N` may
affect execution time.

```rust
use tc_limb::{Choice, ConditionallySelectable, ConstantTimeEq, Limb, LimbArray};

let a = LimbArray::new([Limb::new(3)]);
let b = LimbArray::new([Limb::new(9)]);
let selected = LimbArray::conditional_select(&a, &b, Choice::from_lsb(1));
assert_eq!(selected.ct_eq(&b).unwrap_u8(), 1);
```

Ordinary `==`, `cmp`, zero checks, arithmetic, and division make no constant-time
claim. In particular, division normalization, quotient-estimate corrections,
and GCD loops may depend on the data. `Choice::unwrap_u8` reveals the comparison
result; deployments still require reviewing generated machine code for the
target compiler and hardware.

## Validation

Tests use pseudorandom inputs with a fixed seed for reproducibility and compare
each limb against the independent `num_bigint::BigUint` oracle. Coverage includes
`N = 1, 2, 4, 8`, zero width, full carry/borrow chains, overflow at the highest
limb, double-width accumulation and remainders, all public arithmetic, and
constant-time selection and equality. Full products are also checked by
reconstructing the low and high halves with the arbitrary-precision oracle;
fixed-width truncation and overflow are computed independently from the modulus
and full result.

```text
cargo test -p tc_limb
cargo test -p tc_limb --target i686-pc-windows-msvc
cargo test --workspace
cargo clippy -p tc_limb --all-targets -- -D warnings
cargo fmt -p tc_limb --check
cargo doc -p tc_limb --no-deps
```

The i686 tests require the corresponding Rust target and a working MSVC x86
linker and execution environment. `cargo test` runs the public API examples;
the crate also enables `missing_docs` to prevent undocumented API additions.
