# tc_constant_time

Small, fixed-width primitives for masked selection and equality. The crate is
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
| `!`, `&`, `\|` on `Choice` | Combine predicates without first revealing their bits |
| `ConditionallySelectable::conditional_select(a, b, choice)` | Returns `a` for zero or `b` for one, without value-dependent branches or memory addresses |
| `ConstantTimeEq::ct_eq(a, b)` | Returns a one choice for equality and zero otherwise, without early exit on a mismatch |

Both traits are implemented for `u8`, `u32`, `u64`, and `usize`. Fixed-size arrays
implement each trait when their element type implements it. Array selection
visits every element with the same choice; array equality combines every element
comparison. Empty arrays compare equal, and selecting between empty arrays
returns an empty array. No implementations are provided for `u16`, `u128`, signed
integers, slices, or vectors.

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
wrapping negation to derive the equality bit. Array equality accumulates choices
with `&` over the full array rather than short-circuiting. Preserve those
properties when changing or extending the implementations.

`Choice::from_lsb` passes its bit through `core::hint::black_box`. This is a
best-effort optimization barrier, not a guarantee of constant-time machine code.
Functional tests establish results, not timing behavior; generated code must be
reviewed for the target compiler and hardware. Branching on `unwrap_u8()` or
using a revealed bit as an index is outside the timing contract.

For composite types, select each field through `ConditionallySelectable` and
combine all field comparisons through `Choice` operators. Do not convert a
choice into ordinary control flow to skip work on subsequent fields.

## Validation

The unit test exhaustively checks selection with both choices and equality for
every pair of byte values. Additional tests cover choice normalization and
operators, every bit position of the wider integer types, and array mismatches.
Doctests cover bit normalization, choice operators,
integer and array operations, empty arrays, and custom trait implementations.
The `missing_docs` lint is enabled for public API additions.

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
