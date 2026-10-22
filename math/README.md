# Mathematics crates

This directory contains the workspace's integer, polynomial, finite-field, and
elliptic-curve building blocks. Each subdirectory is an independent Cargo crate.
Depend on the crate that provides the abstraction you need; there is no umbrella
`math` crate.

## Crate overview

| Crate | Functionality | Runtime and allocation |
| --- | --- | --- |
| [`tc_bigint`](tc_bigint/README.md) | Compile-time fixed-width, runtime fixed-width, and arbitrary-precision signed/unsigned integers, encoding, numeric traits, modular and Montgomery arithmetic, and general-purpose probable-prime operations | `no_std`; compile-time fixed-width arithmetic needs no allocator; runtime fixed-width and dynamic integers require `alloc`; `rand_core` enables random operations |
| [`tc_rfc7748`](tc_rfc7748) | X25519 and X448 key generation, public-key derivation, and Diffie-Hellman agreement, plus shared internal Edwards field/base-point arithmetic | Allocation-free `no_std` arithmetic; defaults enable `std` and optional x86 dispatch |

`tc_binpoly` and the elliptic-curve crates `tc_ec_core`, `tc_fp_curve`,
`tc_f2m_curve`, `tc_fp_custom` and `tc_f2m_custom` have graduated to
[TomiCheng/tc_math](https://github.com/TomiCheng/tc_math); this workspace uses
them from crates.io.

`no_std` does not necessarily mean allocation-free. Cargo features are additive,
so another dependency can enable features that a crate disables in its own
dependency declaration.

## Choosing a layer

Use [`tc_constant_time`](https://crates.io/crates/tc_constant_time) when only masked
selection, comparison, or conditional arithmetic is needed. These compiler/timing
primitives come from crates.io and are shared by mathematical backends and
cryptographic algorithms.

Use
`tc_bigint` for integer semantics, signed values, conversions, overflow policies,
or modular arithmetic. `FixedBigUint<N>` and `FixedBigInt<N>` share
internal `LimbArray<N>` storage. Sign interpretation belongs to `FixedBigInt`;
`LimbArray` does not assign a sign to its highest bit. `N` counts limbs, and
`limbs_for_bits(bits)` converts a bit width to that count.

需要常數時間、但寬度到執行期才知道時，選用堆上固定寬度的
`PaddedBigUint`／`PaddedBigInt`。典型場景是 RSA：模數寬度要載入金鑰才確定。
曲線的場寬則是曲線定義的一部分，在編譯期已知，使用 `FixedBigUint<N>`／
`FixedBigInt<N>` 即可；是否需要 CT 並不是選擇 Padded 型別的唯一條件。

For polynomial arithmetic over `GF(2)`, use the published
[`tc_binpoly`](https://crates.io/crates/tc_binpoly); for prime testing and
generation, [`tc_prime`](https://crates.io/crates/tc_prime). For
short-Weierstrass curves, use the published
[`tc_ec_core`](https://crates.io/crates/tc_ec_core) and the curve crates built on
it.

Use `tc_rfc7748` directly for X25519 or X448. It uses dedicated Montgomery-curve
arithmetic rather than the short-Weierstrass traits in `tc_ec_core`. The
[Ed25519](../crypto/tc_ed25519) and [Ed448](../crypto/tc_ed448) signature APIs live
under `crypto/`; they are not signature APIs of `tc_rfc7748`.

## Dependency and feature boundaries

- `tc_bigint` depends on `tc_constant_time`.
- `tc_rfc7748` optionally uses the published `tc_runtime` crate for x86 feature
  detection. Its scalar configuration is available with default features
  disabled.

Ordinary arithmetic is not automatically constant-time because it uses a crate
that also provides constant-time primitives. Consult the individual API contracts.

## Development

Run Cargo commands from the workspace root and select the crate being changed:

```text
cargo test -p tc_bigint --target i686-pc-windows-msvc --locked
cargo doc -p tc_rfc7748 --all-features --no-deps --locked
```

The crate READMEs describe their feature combinations and validation commands.
For limb-backed changes, exercise both x86_64 and i686 because `Word` changes
from 64 to 32 bits. Changes to shared arithmetic also warrant testing the
dependent crates and the workspace.
