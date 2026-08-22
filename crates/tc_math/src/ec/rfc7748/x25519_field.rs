//! Arithmetic in the field `GF(2²⁵⁵ − 19)`, the base field of Curve25519 / X25519.
//!
//! Ported from Bouncy Castle's `Org.BouncyCastle.Math.EC.Rfc7748.X25519Field`
//! (scalar path; the AVX2/SSE2 vector paths are skipped, like binpoly's SIMD).
//!
//! # Representation (ref10, radix 2²⁵·⁵)
//!
//! A field element is [`SIZE`] = 10 signed 32-bit limbs, holding a 255-bit value in
//! roughly **radix 2²⁵·⁵**: each limb holds 25–26 bits (see [`Fe::carry`] for bc's
//! exact per-limb widths — the 25-bit limbs are indices 2, 4, 7, 9). Each limb lives
//! in an `i32` but uses only 25–26 bits, so the spare high bits absorb carries — the
//! representation is **unsaturated**:
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

/// Mask for a 25-bit limb (`2²⁵ − 1`). bc `X25519Field.M25`.
const M25: i32 = 0x01FF_FFFF;
/// Mask for a 26-bit limb (`2²⁶ − 1`). bc `X25519Field.M26`.
const M26: i32 = 0x03FF_FFFF;

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

    /// The multiplicative identity `1` (limb 0 is `1`, the rest `0`). Corresponds to bc
    /// `X25519Field.One`.
    pub const fn one() -> Fe {
        let mut z = [0; SIZE];
        z[0] = 1;
        Fe(z)
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

    /// Field subtraction: limb-wise `i32` subtract, **without carrying**. Limbs are
    /// signed, so a negative difference is fine — the unsaturated representation and a
    /// later `carry` absorb it. Corresponds to bc `X25519Field.Sub` (scalar path).
    pub fn sub(self, rhs: Fe) -> Fe {
        Fe(core::array::from_fn(|i| self.0[i] - rhs.0[i]))
    }

    /// Propagates carries so the (unsaturated) limbs return to range, folding the
    /// top-limb overflow back via `2²⁵⁵ ≡ 19` (the `× 38` factor, in radix 2²⁵·⁵).
    /// The 25-bit limbs are indices 2, 4, 7, 9; the rest are 26-bit.
    ///
    /// Corresponds to bc `X25519Field.Carry`, transcribed verbatim. Rust `i32 >> n` is
    /// an arithmetic shift (like C# `int >>`), so signed limbs carry correctly.
    pub fn carry(self) -> Fe {
        let [mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7, mut z8, mut z9] =
            self.0;

        z2 += z1 >> 26; z1 &= M26;
        z4 += z3 >> 26; z3 &= M26;
        z7 += z6 >> 26; z6 &= M26;
        z9 += z8 >> 26; z8 &= M26;

        z3 += z2 >> 25; z2 &= M25;
        z5 += z4 >> 25; z4 &= M25;
        z8 += z7 >> 25; z7 &= M25;
        z0 += (z9 >> 25) * 38; z9 &= M25; // 2²⁵⁵ ≡ 19 折疊(×38）

        z1 += z0 >> 26; z0 &= M26;
        z6 += z5 >> 26; z5 &= M26;

        z2 += z1 >> 26; z1 &= M26;
        z4 += z3 >> 26; z3 &= M26;
        z7 += z6 >> 26; z6 &= M26;
        z9 += z8 >> 26; z8 &= M26;

        Fe([z0, z1, z2, z3, z4, z5, z6, z7, z8, z9])
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
    fn one_is_limb0() {
        assert_eq!(Fe::one().0, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn add_is_limbwise() {
        let a = Fe([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let b = Fe([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(a.add(b).0, [11, 22, 33, 44, 55, 66, 77, 88, 99, 110]);
        // a + 0 = a
        assert_eq!(a.add(Fe::zero()).0, a.0);
    }

    #[test]
    fn sub_is_limbwise() {
        let a = Fe([10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        let b = Fe([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(a.sub(b).0, [9, 18, 27, 36, 45, 54, 63, 72, 81, 90]);
        // a − a = 0；有號 limb 可為負：b − a
        assert_eq!(a.sub(a).0, [0i32; SIZE]);
        assert_eq!(b.sub(a).0, [-9, -18, -27, -36, -45, -54, -63, -72, -81, -90]);
    }

    #[test]
    fn carry_keeps_zero_and_one() {
        assert_eq!(Fe::zero().carry().0, Fe::zero().0);
        assert_eq!(Fe::one().carry().0, Fe::one().0);
    }

    #[test]
    fn carry_propagates_limb0_overflow() {
        // limb0 = 2²⁶ 溢位 → 進位到 limb1（同值：limb1 的權重就是 2²⁶）。
        let mut a = [0i32; SIZE];
        a[0] = 1 << 26;
        let mut expect = [0i32; SIZE];
        expect[1] = 1;
        assert_eq!(Fe(a).carry().0, expect);
    }

    #[test]
    fn carry_brings_limbs_into_range() {
        // 幾次滿載相加後 limb 超出範圍；carry 後每個 limb 應收回小範圍。
        let full = Fe([M26, M25, M26, M25, M26, M26, M25, M26, M25, M26]);
        let big = full.add(full).add(full); // 3× 滿載
        for (i, &limb) in big.carry().0.iter().enumerate() {
            assert!(limb.unsigned_abs() < (1u32 << 27), "limb {i} = {limb} 未收攏");
        }
    }
}
