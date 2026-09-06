# Mathematics crates

This directory contains the workspace's integer, polynomial, finite-field, and
elliptic-curve building blocks. Each subdirectory is an independent Cargo crate.
Depend on the crate that provides the abstraction you need; there is no umbrella
`math` crate.

## Crate overview

| Crate | Functionality | Runtime and allocation |
| --- | --- | --- |
| [`tc_constant_time`](tc_constant_time/README.md) | `Choice`, masked conditional selection, and equality for supported unsigned integers and fixed-size arrays | Core-only `no_std`; no dependencies or heap allocation |
| [`tc_limb`](tc_limb/README.md) | `Limb` and `LimbArray<N>`: unsigned fixed-width storage, carry/borrow arithmetic, wide multiplication, division, GCD, and bit operations | Core-only `no_std`; no heap allocation |
| [`tc_bigint`](tc_bigint/README.md) | Fixed-width and arbitrary-precision signed/unsigned integers, encoding, numeric traits, modular and Montgomery arithmetic, and general-purpose probable-prime operations | `no_std`; fixed-width arithmetic needs no allocator; dynamic integers require `alloc`; `rand_core` enables random operations |
| [`tc_binpoly`](tc_binpoly/README.md) | Polynomial arithmetic over `GF(2)`, including carryless multiplication, squaring, reduction, and inversion; fixed and dynamic representations | `no_std`; fixed storage and core arithmetic work without allocation; defaults enable `alloc`, `std`, and optional x86 acceleration |
| [`tc_prime`](tc_prime/README.md) | FIPS 186-4 small-factor screening, Miller-Rabin tests, enhanced Miller-Rabin results, and optional Shawe-Taylor provable-prime generation | `no_std`; fixed-width testing works without allocation; `alloc` is enabled by default; `digest` enables Shawe-Taylor and requires `alloc` |
| [`tc_ec_core`](tc_ec_core/README.md) | Shared field, curve, and point traits; scalar and multi-scalar algorithms, batch normalization, precomputation, GLV interfaces, and separate secret-scalar APIs | `no_std` with `alloc` |
| [`tc_fp_curve`](tc_fp_curve) | Generic prime-field short-Weierstrass curves using Montgomery arithmetic, with `FpCurve`, `FpFieldElement`, `FpPoint`, and named-curve constructors | `no_std` with `alloc` |
| [`tc_fp_custom`](tc_fp_custom) | Specialized SEC and SM2 prime-field curves, fixed-width field kernels and point formulas, and secp256k1 GLV support | `no_std` with `alloc`; field kernels use fixed-width storage |
| [`tc_f2m_curve`](tc_f2m_curve) | Generic binary-field short-Weierstrass curves, trinomial/pentanomial fields, named curves, and tau-adic multiplication for Koblitz curves | `no_std` with `alloc` |
| [`tc_f2m_custom`](tc_f2m_custom) | Specialized SEC binary fields and named curves, reusing the generic binary-curve point formulas | `no_std` with `alloc`; field elements use fixed-width storage |
| [`tc_rfc7748`](tc_rfc7748) | X25519 and X448 key generation, public-key derivation, and Diffie-Hellman agreement, plus shared internal Edwards field/base-point arithmetic | Allocation-free `no_std` arithmetic; defaults enable `std` and optional x86 dispatch |

`no_std` does not necessarily mean allocation-free. The curve crates use `alloc`
for their supporting structures even when individual field elements have fixed
storage. Cargo features are additive, so another dependency can enable features
that a crate disables in its own dependency declaration.

## Choosing a layer

Use `tc_constant_time` when only masked selection or equality is needed. It
contains compiler/timing primitives rather than mathematical operations; its
location here avoids a separate `core/` directory containing just one crate.

Use `tc_limb` to implement fixed-width arithmetic over raw unsigned limbs. Use
`tc_bigint` for integer semantics, signed values, conversions, overflow policies,
or modular arithmetic. `FixedBigUint<N>` and `FixedBigInt<N>` share
`tc_limb::LimbArray<N>` storage. Sign interpretation belongs to `FixedBigInt`;
`LimbArray` does not assign a sign to its highest bit. `N` counts limbs, and
`tc_limb::Word::BITS` determines their platform-dependent width.

Use `tc_binpoly` for polynomial arithmetic over `GF(2)`. Its bits represent
polynomial coefficients, so its arithmetic is distinct from integer arithmetic.
Use `tc_prime` for the FIPS/Bouncy Castle prime-testing and generation interfaces;
it builds on `tc_bigint` and accepts both fixed and dynamic integer types where
the selected features permit them.

For short-Weierstrass curves, `tc_ec_core` defines the shared contracts and
algorithms. `tc_fp_curve` and `tc_f2m_curve` supply generic prime-field and
binary-field implementations. Their `*_custom` counterparts provide specialized
named fields and curves while retaining the common traits. `tc_fp_custom` has
its own field and point kernels; `tc_f2m_custom` supplies specialized fields to
the point machinery in `tc_f2m_curve`.

Use `tc_rfc7748` directly for X25519 or X448. It uses dedicated Montgomery-curve
arithmetic rather than the short-Weierstrass traits in `tc_ec_core`. The
[Ed25519](../crypto/tc_ed25519) and [Ed448](../crypto/tc_ed448) signature APIs live
under `crypto/`; they are not signature APIs of `tc_rfc7748`.

## Dependency and feature boundaries

- `tc_limb` depends on `tc_constant_time`. `tc_bigint` depends on both, and
  `tc_prime` builds on `tc_bigint`. There is no reverse dependency from
  `tc_limb` to `tc_bigint`.
- `tc_ec_core` depends on `tc_constant_time` without choosing an integer or field
  backend. Concrete curve crates supply those implementations.
- `tc_binpoly` and `tc_rfc7748` optionally use the published `tc_runtime` crate
  for x86 feature detection. Their scalar configurations are available with
  default features disabled.
- `tc_prime` optionally depends on `crypto/tc_digest` for Shawe-Taylor generation.
  Callers supply the digest implementation and random source where required.

Ordinary arithmetic is not automatically constant-time because it uses a crate
that also provides constant-time primitives. Consult the individual API contracts,
especially the distinction between public-scalar algorithms and the `Secret*`
interfaces in `tc_ec_core`.

## Development

Run Cargo commands from the workspace root and select the crate being changed:

```text
cargo test -p tc_limb --locked
cargo test -p tc_bigint --target i686-pc-windows-msvc --locked
cargo clippy -p tc_constant_time --all-targets --locked -- -D warnings
cargo doc -p tc_prime --all-features --no-deps --locked
```

The crate READMEs describe their feature combinations and validation commands.
For limb-backed changes, exercise both x86_64 and i686 because `Word` changes
from 64 to 32 bits. Changes to shared arithmetic also warrant testing the
dependent crates and the workspace.
