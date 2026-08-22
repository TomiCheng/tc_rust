//! Arithmetic in the field `GF(2²⁵⁵ − 19)`, the base field of Curve25519 / X25519.
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748.X25519Field`
//! (scalar path; the AVX2/SSE2 vector paths are skipped, like binpoly's SIMD).
//!
//! # Representation (ref10, radix 2²⁵·⁵)
//!
//! A field element is [`SIZE`] = 10 signed 32-bit limbs, holding a 255-bit value in
//! **radix 2²⁵·⁵**: even limbs carry 26 bits, odd limbs 25 bits
//! (`5·26 + 5·25 = 255`). Each limb lives in an `i32` but uses only 25–26 bits, so
//! the spare high bits absorb carries — the representation is **unsaturated**:
//! addition is limb-wise `i32` add with no immediate carry, and [`carry`]/`normalize`
//! reconcile later. Products of two ~26-bit limbs (~52 bits) accumulate in `i64`, so
//! no 128-bit arithmetic is needed.
//!
//! All operations are **constant-time** (straight-line, no data-dependent branches):
//! this field is the constant-time answer for its curve, unlike the variable-time
//! generic Fp/F2m layers.
//
// TODO(x25519-field-5limb): on 64-bit targets a radix-2⁵¹ representation (5 × u64,
// products in u128) is substantially faster — ~1/4 the partial products and full use
// of the 64-bit multiplier (as in TweetNaCl / ref10-64 / fiat-crypto). It is a
// *separate* implementation, not a limb-width cfg of this one (limb count, radix, and
// the ×19/38/76 reduction constants all change together). Deferred as a 64-bit
// optimization; this 10×i32 port is the faithful, all-platform baseline.

/// Number of `i32` limbs in a field element (radix 2²⁵·⁵).
pub const SIZE: usize = 10;

/// An element of `GF(2²⁵⁵ − 19)` in the ref10 radix-2²⁵·⁵ representation: [`SIZE`]
/// signed limbs, unsaturated (each limb uses 25–26 of its 32 bits). Values are not
/// necessarily reduced/normalized between operations; [`carry`]/`normalize` bring a
/// limb array back into range when needed.
///
/// `Copy` — it is a small fixed array on the stack, so value-returning arithmetic
/// costs no heap allocation (cleaner than bc's out-parameter style).
///
/// The limbs are **private**: they are an unsaturated, non-unique internal encoding
/// (the same field value has many limb representations), so all access goes through
/// this module's value-semantic API (arithmetic, `encode`/`decode`, constants).
#[derive(Clone, Copy, Debug)]
pub struct Fe([i32; SIZE]);

impl Fe {
    /// The additive identity `0` (all limbs zero). Corresponds to bc `X25519Field.Zero`
    /// (bc zeroes an out-parameter; we return a value — `Fe` is a `Copy` stack array,
    /// so this is allocation-free).
    pub const fn zero() -> Fe {
        Fe([0; SIZE])
    }

    /// Field addition: limb-wise `i32` add, **without carrying** — the unsaturated
    /// representation absorbs the growth. Corresponds to bc `X25519Field.Add` (scalar
    /// path; the AVX2/SSE2 vector paths are skipped — see `TODO(x25519-simd)`).
    ///
    /// The result is *not* normalized: chain a few `add`/`sub`, then `carry` (added
    /// later) before a `mul`/`sqr`, which need limbs back in range.
    pub fn add(self, rhs: Fe) -> Fe {
        Fe(core::array::from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

// TODO(x25519-simd): bc's Add/Mul/etc. have AVX2/SSE2 vector paths behind runtime
// feature detection (Sse2.IsEnabled / Avx2.IsEnabled). We port only the scalar path.
// A portable runtime-dispatched SIMD backend in no_std needs hand-rolled CPUID
// (+ XGETBV for AVX) cached in an AtomicU8; `is_x86_feature_detected!` is std-only.
// Deferred; release builds already auto-vectorize the simple loops (add/sub) to SSE2.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_has_all_limbs_clear() {
        assert_eq!(Fe::zero().0, [0i32; SIZE]);
    }

    #[test]
    fn add_is_limbwise() {
        let a = Fe([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let b = Fe([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(a.add(b).0, [11, 22, 33, 44, 55, 66, 77, 88, 99, 110]);
        // a + 0 = a
        assert_eq!(a.add(Fe::zero()).0, a.0);
    }
}
