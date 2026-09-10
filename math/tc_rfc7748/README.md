# tc_rfc7748

RFC 7748 Montgomery-curve Diffie-Hellman: X25519 and X448. The crate is
`no_std` and allocation-free. Inputs and outputs are fixed-size byte arrays;
key generation accepts a caller-supplied RNG.

It deliberately does not implement generic short-Weierstrass point traits.
Montgomery curves use a dedicated ladder over their own field
representation, and forcing them through the generic point machinery would cost
both speed and clarity. Signature schemes belong to higher layers;
RFC 8032 implementations can reuse
the Edwards and field arithmetic exposed here.

## API

`x25519` and `x448` expose the same shape, differing only in sizes.

| Item | X25519 | X448 |
| --- | --- | --- |
| `SCALAR_SIZE` / `POINT_SIZE` | 32 | 56 |
| `generate_private_key(rng)` | ✓ | ✓ |
| `clamp_private_key(&mut key)` | ✓ | ✓ |
| `generate_public_key(&key)` | ✓ | ✓ |
| `calculate_agreement(&key, &peer)` | ✓ | ✓ |
| `scalar_mult(&k, &u)` | ✓ | ✓ |
| `scalar_mult_base(&k)` | ✓ | ✓ |
| `precompute()` | no runtime table construction | empty `const fn` |

`calculate_agreement` returns `Option`. `None` means the shared secret came out
all zero, as with a low-order peer point. This API chooses to reject such
agreements; the caller must handle `None`, not replace it with a zero secret.
[RFC 7748 §6](https://www.rfc-editor.org/rfc/rfc7748.html#section-6) permits this
check rather than requiring it of every implementation. The check scans the
whole output instead of stopping at the first non-zero byte; returning
`Some` or `None` then reveals only whether the result was all zero.

`generate_private_key` clamps before returning, so a key it produces needs no
further preparation. `clamp_private_key` exists for keys that arrive from
elsewhere.

## Field backends

The two curves use different representations, not one parameterised field.

| | Representation | Notes |
| --- | --- | --- |
| X25519 | 10 × `i32`, radix 2²⁵·⁵ | portable baseline; SSE2 and AVX2 paths selected at runtime on x86 |
| X448 | 16 × `u32`, radix 2²⁸ | portable baseline; AVX2 convolution selected at runtime on x86 |

The X25519 field is the faithful all-platform port. A 5 × `u64` radix-2⁵¹
variant would be substantially faster on 64-bit targets, but it is a separate
implementation rather than a limb-width switch — the limb count, radix and
reduction constants all change together — so it is deferred rather than
half-built. See the note at the top of `src/x25519_field.rs`.

`scalar_mult_base` for X25519 does not run the ladder from the base point. It
multiplies on the twisted Edwards curve using a compile-time table, then
converts the result back to a Montgomery `u` coordinate, which is the usual way
to make fixed-base multiplication faster than the variable-base one.

## Timing

The public scalar-multiplication paths use fixed schedules. Montgomery ladders
use masked conditional swaps; X25519 fixed-base multiplication scans complete
table rows and selects entries with masks. The final inverse uses a fixed
addition chain for X25519 and a fixed public-exponent loop for X448.
CPU dispatch depends on public processor capabilities, not the scalar.

Clamping uses only masks at fixed byte positions. Key generation reads a fixed
number of bytes and then clamps, but its overall timing depends on the caller's
RNG. Agreement's final `Option` exposes the all-zero rejection described above.

These are source-level timing properties, not a machine-code or hardware timing
audit. The hidden field modules also contain variable-time helpers for public
inputs; their visibility does not make every helper suitable for secrets.

## Features

| Feature | Default | Effect |
| --- | :-: | --- |
| `std` | ✓ | lets the runtime dispatch layer use the standard library |
| `x86` | ✓ | enables SSE2/AVX2 detection and dispatch on x86 and x86_64 |

`--no-default-features` gives a pure scalar `no_std` build with no optional
dependencies. Dispatch uses public CPU feature detection on supported targets.
`x25519::precompute()` only passes a reference to the static base table through
`black_box`; it neither builds a table nor warms CPU detection, and does not
promise to preload the table. `x448::precompute()` is an empty `const fn`.
Both entry points preserve Bouncy Castle's API shape. Bouncy Castle builds its
Edwards tables lazily under a lock; this crate's X25519 table is compiled in,
and its X448 fixed-base path uses the ladder without a table.

## Unstable modules

`ed25519_base`, `x25519_field` and `x448_field` are `#[doc(hidden)]`. They are
public so that Ed25519 and Ed448 implementations in other crates can share this
arithmetic without a dependency cycle. Rust has no visibility restricted to a
particular external crate. These modules promise neither stable APIs/ABIs nor a
stable limb layout, and do not give all helpers a uniform timing contract.
Use `x25519` and `x448` for the supported key-agreement interface.

## Example

RFC 7748 §6.1 fixed test inputs, matching the `calculate_agreement` doctest:

```rust
use tc_rfc7748::x25519;

let alice_private = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
];
let bob_public = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
];
let expected_shared = [
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
    0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
    0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
];
assert_eq!(
    x25519::calculate_agreement(&alice_private, &bob_public),
    Some(expected_shared),
);

// 對方送入低階點 u = 0：必須拒絕，不可取預設的全零陣列。
let low_order_point = [0; x25519::POINT_SIZE];
let rejected = x25519::calculate_agreement(&alice_private, &low_order_point);
assert!(rejected.is_none());
```

## Testing

RFC 7748 test vectors cover both curves, including the iterated vectors. The
1000-iteration X448 case is expensive, so it is marked `#[ignore]`:

```bash
cargo test -p tc_rfc7748
cargo test -p tc_rfc7748 --doc
cargo rustdoc -p tc_rfc7748 --all-features -- -D warnings
cargo test -p tc_rfc7748 -- --ignored
```

## Reference

[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), especially §5.2 and
§6, supplies the scalar-multiplication and Diffie-Hellman vectors in the docs.

Ported from the [Bouncy Castle C#](https://github.com/bcgit/bc-csharp)
implementation. This attribution does not imply compatibility certification or
endorsement.
