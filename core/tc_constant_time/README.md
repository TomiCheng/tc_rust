# tc_constant_time

Shared primitives for masked selection, comparison, and conditional arithmetic. The crate is
`no_std`, has no dependencies or feature flags, and uses no `alloc`, heap
allocation, or `unsafe` code.

Requires Rust 1.85 or later (edition 2024).

`tc_constant_time` provides compiler/timing primitives rather than mathematical
operations. It lives under `core/` so both cryptographic algorithms and
mathematical backends can share it without depending on each other's layer.

## API

| Item | Contract |
| --- | --- |
| `Choice::from_lsb(value)` | Keeps only the lowest bit of a `u8`; even inputs become zero and odd inputs become one |
| `Choice::unwrap_u8()` | Reveals the choice as zero or one |
| `!`, `&`, `\|`, `^` on `Choice` | Combine predicates without revealing bits or adding optimization barriers |
| `ConditionallySelectable::conditional_select(a, b, choice)` | Returns `a` for zero or `b` for one, without value-dependent branches or memory addresses |
| `conditional_assign` | Replaces a value for one and leaves it unchanged for zero |
| `conditional_swap` | Swaps two values for one and leaves them unchanged for zero |
| `ConditionallyNegatable::conditional_negate` | Negates in place with wrapping arithmetic for one |
| `ConstantTimeEq::ct_eq(a, b)` | Returns a one choice for equality and zero otherwise, without early exit on a mismatch |
| `ConstantTimeOrd::{ct_lt, ct_gt, ct_le, ct_ge}` | Unsigned ordering that returns a `Choice` |
| `fixed_time_eq(a, b)` | Compares byte slices and deliberately reveals a `bool` for public verification results |

| Types | Selection, assignment, swap | Wrapping negation | Equality | Ordering |
| --- | --- | --- | --- | --- |
| `u8`, `u16`, `u32`, `u64`, `u128`, `usize` | Yes | Yes | Yes | Yes |
| `i32`, `i64` | Yes | Yes | Yes | No |
| `[T; N]` | When supported by `T` | When supported by `T` | When supported by `T` | No |
| `[T]` | No | No | When supported by `T` | No |

Array updates visit every element with the same choice. Assignment and swap
operate element by element without copying the entire array. Equality scans all
elements for equal lengths. Empty arrays and slices compare equal.

Slice lengths are public: unequal lengths return a zero choice immediately.
`fixed_time_eq` applies that same rule and returns `false`. Use it for tag or
checksum verification only when the result is intended to be public. It is the
crate's only convenience function that converts a `Choice` to `bool`; retain a
`Choice` with `ct_eq` when combining secret predicates.

Negation wraps modulo the integer width, so negating `i32::MIN` or `i64::MIN`
leaves the value unchanged. `ConstantTimeOrd` is intentionally unsigned-only;
array ordering is left to higher layers because limb order is a domain choice.

`Choice` supports `Copy` and `Clone` and keeps its field private. It does not
provide an implicit conversion to `bool`. `from_lsb` accepts any byte, but it is
not a nonzero test: `Choice::from_lsb(2)` is zero.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
tc_constant_time = "0.1.0"
```

```rust
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};

let expected = [1_u8, 2, 3, 4];
let received = [1_u8, 2, 3, 4];
let enabled = Choice::from_lsb(1);
let accept = expected.ct_eq(&received) & enabled;
let selected = <[u8; 4]>::conditional_select(&[0; 4], &received, accept);
assert_eq!(selected, received);
assert_eq!(accept.unwrap_u8(), 1);
```

API documentation contains executable examples for individual methods, empty
arrays, and implementing the traits for composite types.

## Timing and implementation constraints

The contracts concern secret values. Public array lengths and other public
parameters may affect execution time. Array implementations inherit the timing
properties of their elements; an implementation that branches on secret data
cannot become constant-time merely by being placed in an array.

Integer selection builds an all-zero or all-one mask and combines the operands
with bitwise operations. Integer equality combines the XOR difference with its
wrapping negation to derive the equality bit. Array and slice equality accumulate
choices with `&` over all elements rather than short-circuiting. Preserve those
properties when changing or extending the implementations.

`Choice::from_lsb` passes its bit through `core::hint::black_box`; integer
comparison results enter through that constructor. Boolean combinators directly
preserve the zero-or-one invariant without another barrier or redundant mask.
The barrier is a
best-effort optimization barrier, not a guarantee of constant-time machine code.
Functional tests establish results, not timing behavior; generated code must be
reviewed for the target compiler and hardware. Branching on `unwrap_u8()` or
using a revealed bit as an index is outside the timing contract.

Unsigned ordering derives the subtraction borrow bit without a wider integer,
including for `u128`. Signed equality first casts to the corresponding unsigned
type so its final shift is logical, not arithmetic.

For composite types, select each field through `ConditionallySelectable` and
combine all field comparisons through `Choice` operators. Do not convert a
choice into ordinary control flow to skip work on subsequent fields.

## Validation

Unit tests live in `src/tests/`, grouped into `choice`, `integers`, `array`,
`slice`, and `traits` modules. The `api` module retains the cross-API byte
exhaustion test; `src/tests.rs` declares all test modules.

The unit test exhaustively checks selection with both choices and equality for
every pair of byte values. All new byte APIs are also compared against public
reference operations over all 256-by-256 input pairs. Additional tests cover
choice normalization and operators, every bit boundary of each unsigned width,
signed extremes, array updates, non-`Copy` default implementations, and slice
scan behavior after a mismatch.
Doctests cover bit normalization, choice operators,
integer and array operations, empty arrays, and custom trait implementations.
Missing public documentation and unsafe code are rejected by crate-level lints.

Run these commands from the workspace root:

```text
cargo test -p tc_constant_time --locked
cargo test -p tc_constant_time --target i686-pc-windows-msvc --locked
cargo check -p tc_constant_time --no-default-features --locked
cargo clippy -p tc_constant_time --all-targets --locked -- -D warnings
cargo fmt -p tc_constant_time --check
cargo doc -p tc_constant_time --no-deps --locked
```

The i686 run exercises a 32-bit `usize` and requires the corresponding Rust
target and a working MSVC x86 linker and execution environment.

Before a release, check the archive contents and run publication validation
from a committed checkout:

```text
cargo package -p tc_constant_time --list --locked
cargo publish -p tc_constant_time --dry-run --locked
```

The archive includes both license texts, this README, and the source. The
publication dry run packages and verifies the crate without uploading it.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
