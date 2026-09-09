# tc_zeroize

Explicit memory erasure with volatile writes and opt-in scope guards. The crate
is `no_std`, has no dependencies or feature flags, and uses no `alloc` or heap
allocation. Its primitive implementations use small, documented `unsafe` blocks
for volatile writes.

This crate is incubating in `tc_rust`. Publication metadata, a changelog, and
crate-local license files are deferred until its move to `tc_core`.

## API

| Item | Contract |
| --- | --- |
| `Zeroize::zeroize(&mut self)` | Explicitly erases the contents of the current value |
| `ZeroizeOnDrop` | Marks a type whose own destructor performs erasure; the marker generates no behavior |
| `Zeroizing::new(value)` | Owns a value and calls its `zeroize` before dropping it |
| `Deref` / `DerefMut` on `Zeroizing<T>` | Borrows the guarded value for ordinary operations |

| Types | Result of `zeroize` |
| --- | --- |
| `u8`, `u16`, `u32`, `u64`, `u128`, `usize` | Zero |
| `i8`, `i16`, `i32`, `i64`, `i128`, `isize` | Zero |
| `bool` | `false` |
| `char` | `'\0'` |
| `[T; N]`, `[T]` where `T: Zeroize` | Every element is cleared; length is preserved |
| `Option<T>` where `T: Zeroize` | A present payload is cleared, then dropped, and the option becomes `None` |

Empty arrays and slices are supported. Slice lengths are public. Array and slice
implementations visit every element and inherit the erasure behavior of `T`.
An option branches on whether a value is present. This is not a constant-time API.

## Capability and policy

`Zeroize` provides a capability, not a mandatory lifetime policy. General-purpose
storage types do not know whether their contents are secret; they should offer
explicit erasure without automatically imposing cleanup on all uses.

Types that know they hold secrets, such as private-key containers and private
RSA engines, can choose the `ZeroizeOnDrop` policy. Implementors must write their
own `Drop` implementation and call `Zeroize::zeroize` there. The marker alone
does not enforce or implement this behavior.

`Zeroizing<T>` applies that policy to a local value. The guard implements neither
`Clone` nor `Copy`. Dereferencing it can still allow a caller to copy or clone the
inner value; those separate values are not guarded. No downstream crate is wired
to this capability in this initial version.

## Usage

For a crate directly under `crypto/` or `math/` in this workspace:

```toml
[dependencies]
tc_zeroize = { version = "0.1.0", path = "../../core/tc_zeroize" }
```

```rust
use tc_zeroize::{Zeroize, Zeroizing};

let mut scratch = [1_u8, 2, 3, 4];
scratch.zeroize();
assert_eq!(scratch, [0; 4]);

let mut optional = Some([7_u32, 9]);
optional.zeroize();
assert_eq!(optional, None);

{
    let mut secret = Zeroizing::new([42_u8; 32]);
    secret[0] = 7;
    assert_eq!(secret[0], 7);
} // The guard clears its current array before dropping it.
```

API documentation also has executable examples for implementing both traits.

## Mechanism and limitations

Primitive erasure uses `core::ptr::write_volatile` to prevent deletion of the
stores and ends with `compiler_fence(Ordering::SeqCst)` to constrain compiler
reordering. Composite implementations delegate to their contents. Every unsafe
block documents pointer validity and the validity of the replacement value.

These operations do not flush caches or supply a hardware memory barrier. They
do not erase copies left elsewhere by the compiler or operating system, such as
registers, stack spills, swap, or core dumps. Padding bytes are not covered.

`Copy` values permit implicit copies on by-value use. Clearing one binding does
not clear other copies; `FixedBigUint` is a relevant example in `tc_rust`. A
`Copy` type cannot implement `Drop`, so it cannot perform its own scope-exit
cleanup. Even moves of non-`Copy` types can leave bytes at an old location.
`Zeroizing` clears only its current contents, not those old copies.

Collection reallocations can leave data in inaccessible old buffers. `Vec<T>`
and `String` are not supported in version 0.1, and there is no `alloc` feature.
Clearing only a collection's live slice does not clear its spare capacity or any
previous allocation. This crate makes no such collection-wide guarantee.

Drop-based cleanup requires the destructor to run. Forgetting or leaking the
guard, or aborting the process, bypasses cleanup. A panicking custom `zeroize`
implementation can also leave a composite value partially cleared.

## Validation

Integration tests import the public API and cover every supported primitive,
empty and nested containers, non-`Copy` elements, slice boundaries, clearing
before a payload's destructor, and guard cleanup on scope exit and unwinding.
Crate and type documentation contains executable examples. Missing public docs
and unsafe operations without explicit unsafe blocks in unsafe functions are
rejected by crate-level lints.

Functional tests establish resulting values and cleanup order. They do not
prove that a compiler preserves the wipe; generated code must be inspected for
the target compiler and hardware when validating that property.

Run these commands from the `tc_rust` workspace root:

```text
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc -p tc_zeroize --no-deps
```

## License

Licensed under either the [MIT license](../../LICENSE-MIT) or the
[Apache License, Version 2.0](../../LICENSE-APACHE), at your option.
