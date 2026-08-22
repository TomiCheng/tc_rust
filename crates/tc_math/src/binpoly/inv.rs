//! Multiplicative inversion operator for a binary field `GF(2ⁿ)`.
//!
//! Mirrors Bouncy Castle's `IBinPolyInv`. The only implementation (today) is
//! Itoh–Tsujii, built on a [`super::mul::BinPolyMul`] (it drives that operator's
//! `square_n` / `multiply` along an addition chain) — corresponding to bc's
//! `BinPolys.Inv.ItohTsujii(mul)`. Inversion requires an irreducible reduction
//! polynomial (a genuine field), so it pairs with trinomial/pentanomial reducers,
//! never the binomial one.

/// Multiplicative inversion in `GF(2ⁿ)`, operating on bit-packed `u64`-limb slices.
///
/// `Send + Sync` (like [`super::mul::BinPolyMul`]) lets the operator be shared across
/// threads behind an `Arc`; the implementation is a stateless, immutable operator.
pub trait BinPolyInv: Send + Sync {
    /// The field degree `n`.
    fn n(&self) -> usize;

    /// The number of `u64` limbs a field element occupies (`⌈n / 64⌉`).
    fn size(&self) -> usize;

    /// Computes `z = x⁻¹ mod r(x)`. `x` and `z` are `size` limbs and must be
    /// distinct; `x` must be non-zero.
    fn invert(&self, x: &[u64], z: &mut [u64]);
}
