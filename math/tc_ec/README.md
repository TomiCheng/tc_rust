# tc_ec

A pure-Rust finite-field and elliptic-curve foundation ported from the Bouncy
Castle C# library (`bc-csharp`, baseline commit `f027bbe1`) as a learning
project. Arbitrary-precision integers now live in the separate
[`tc_bigint`](../tc_bigint) crate.

- **`no_std` + `alloc`**: the `std` feature is on by default;
  `--no-default-features` switches both `tc_ec` and its `tc_bigint` dependency
  to `no_std`.
- **Caller-provided randomness**: depends on `rand_core`; the library never calls
  `rand::rng()` internally.

---

## Module overview

| Module | Contents | bc counterpart |
|--------|----------|----------------|
| `binpoly` | Binary polynomials over GF(2) (the layer underneath F2m) | binary part of `Math.Raw` |
| `raw::Nat` | Const-generic fixed-size limb integers (foundation for custom Fp) | `Math.Raw.Nat*` |
| `ec` | Elliptic curves: affine Fp/F2m curves and points, SEC named curves, rfc7748 (X25519) | `Math.EC` |

Arbitrary-precision integer operations are provided by `tc_bigint`; import
`tc_bigint::BigInteger` directly when an application needs them.

---

## Completeness (surveyed 2026-08-26)

> **Layers differ in kind, not just degree. The lower number-theory layer and the EC
> field arithmetic are functionally complete; what the EC layer still lacks splits into
> three distinct buckets — missing features, missing optimizations, and missing
> constant-time guarantees — which are easy to conflate but shouldn't be.**

| Module | Public API | Status |
|--------|:---:|--------|
| `binpoly` | ✅ complete | no `todo!` |
| `raw::Nat` | ✅ complete | — |
| `ec` Fp/F2m **field arithmetic** | ✅ complete | `fp_field_element` / `f2m_field_element`: add/sub/mul/div/neg/square/invert/sqrt (+ fused, trace/half-trace) all implemented and tested |
| `ec::rfc7748` **X25519** | 🟡 main path complete | Montgomery ladder + RFC 7748 vectors verified, constant-time; see gaps below |
| `ec` Fp/F2m **point layer** | 🟡 affine works | affine add/double/neg + double-and-add scalar mul are correct; gaps are optimization/security, see below |

**X25519 is complete and usable** (the first usable primitive), but has known gaps:
- `X25519Field::are_equal` / `is_zero_var` (the constant-time predicates) are still
  `todo!()` — the ladder does not need them, so they are unimplemented for now.
- `ScalarMultBase` (public key from private key) is not done — it needs the Edwards
  base-point multiplication machinery.

**What the EC layer still lacks, split by kind:**

1. **Missing features** (a capability that does not exist yet):
   - F2m serialization & metadata: `F2mFieldElement::from_big_integer`, `get_encoded` /
     `encode_to` (SEC point encoding), and the X9.62 accessors (`m`/`k1`/`k2`/`k3`/
     `representation`/`field_name`) — deferred until the point/codec layer needs them
     (see `TODO(ec-f2m)` in `f2m_field_element.rs`).

2. **Missing optimizations** (a correct baseline exists; only a faster path is absent):
   - **Projective coordinate systems** — affine gives correct results; projective would
     defer the per-operation field inversion for speed. `fp_point`/`f2m_point` `todo!()`
     on any non-affine coordinate system, but nothing constructs such points today, so
     affine is the only reachable path.
   - **WNAF / windowed scalar multiplication** — double-and-add is functionally complete;
     WNAF is only faster.

3. **Missing constant-time guarantees** — see the security warning below.

**SEC named curves**: 33 curves in `named_curves.rs` — `secp112r1/r2`, `secp128r1/r2`,
`secp160k1/r1/r2`, `secp192k1/r1`, `secp224k1/r1`, `secp256k1`, `secp256r1` (P-256),
`secp384r1`, `secp521r1`; `sect113r1/r2`, `sect131r1/r2`, `sect163k1/r1/r2`,
`sect193r1/r2`, `sect233k1/r1`, `sect239k1`, `sect283k1/r1`, `sect409k1/r1`,
`sect571k1/r1`.

---

## ⚠️ Security warning (a gap beyond mere "optimization")

**Not production-ready.** The EC Fp/F2m **inverse and scalar multiplication are
variable-time** and **leak timing**. This is a matter of security correctness, not
just speed:

- `FpFieldElement` inversion goes through `tc_bigint::BigInteger::mod_inverse` (extended Euclid,
  variable-time); bc's counterpart is constant-time safegcd (`Mod.ModOddInverse`).
- Scalar multiplication uses double-and-add, whose branches and access patterns depend
  on the scalar bits.

Closing this matters more than any Karatsuba/SIMD work — it decides whether the code
can sign anything real. X25519 is the only path that is already constant-time.

---

## Optimizations not yet done (intentional: correct & interoperable first, fast later)

The current code is a **faithful baseline**; almost no optimization has been applied:

- **binpoly**: no **PCLMUL/PMULL SIMD** backend, no fast squaring, no large-operand
  Karatsuba, no reduction fast-path.
- **X25519 field**: a 10×i32 all-platform baseline — no 64-bit **radix-2⁵¹** (5×u64)
  representation and no **AVX2/SSE2 SIMD**.
- **EC**: projective coordinates and WNAF scalar multiplication — see bucket 2 of the
  EC breakdown above.

(Each has a corresponding `TODO(...)` marker in the source.)

---

## Build & test

```bash
# standard tests (64-bit)
cargo test -p tc_ec

# no_std build
cargo build -p tc_ec --no-default-features

# 32-bit branch check (WOW64, exercises the limb_x32 path)
cargo test -p tc_ec --target i686-pc-windows-msvc

```
