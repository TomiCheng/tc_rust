//! Prime-field elements for elliptic curves.
//!
//! Corresponds to `FpFieldElement` in Bouncy Castle C#
//! (`Org.BouncyCastle.Math.EC.FpFieldElement`). Binary-field (F2m) elements and
//! the common field-element abstraction will live in sibling modules later.

use core::ops::{Add, Sub};

use crate::big_integer::BigInteger;

/// An element of the prime field GF(p).
///
/// Holds the field modulus `q` (the prime p) alongside the value `x`, with the
/// invariant `0 <= x < q`. Arithmetic is performed modulo `q`.
///
/// Mirrors `FpFieldElement` from Bouncy Castle. Each element carries its own
/// copy of `q` and the reduction residue `r`; both originate from the curve
/// (`FpCurve`), which computes `r` once via [`FpFieldElement::calculate_residue`]
/// and threads it into every element it creates.
#[derive(Clone)]
pub struct FpFieldElement {
    // 體域質數（模數）。
    q: BigInteger,
    // 元素值，不變式：0 <= x < q。
    x: BigInteger,
    // 快速模約簡用的預算殘值，由曲線建構時算好傳入；None 表示沒有快速形式，
    // 退回通用取模。目前僅存放，實際使用在 mod_reduce 快速路徑實作後。
    r: Option<BigInteger>,
}

impl FpFieldElement {
    /// Low-level constructor mirroring Bouncy Castle's internal
    /// `FpFieldElement(q, r, x)`: stores the value directly without reducing or
    /// range-checking it.
    ///
    /// The caller (the curve's `from_big_integer`) is responsible for ensuring
    /// `0 <= x < q` and for supplying `r` from [`calculate_residue`]. This is
    /// crate-internal (bc marks it `internal`); external callers construct field
    /// elements through the curve.
    ///
    /// [`calculate_residue`]: FpFieldElement::calculate_residue
    pub(crate) fn new(q: BigInteger, x: BigInteger, r: Option<BigInteger>) -> Self {
        FpFieldElement { q, x, r }
    }

    /// Creates a new element in the same field (sharing `q` and `r`) holding the
    /// value `x`, which the caller must already have reduced into `[0, q)`.
    ///
    /// Corresponds to the `new FpFieldElement(q, r, result)` pattern used
    /// throughout Bouncy Castle's arithmetic methods.
    fn with_value(&self, x: BigInteger) -> Self {
        FpFieldElement {
            q: self.q.clone(),
            x,
            r: self.r.clone(),
        }
    }

    /// Computes the reduction residue `r` used to speed up reduction modulo `q`,
    /// matching Bouncy Castle's `FpFieldElement.CalculateResidue`.
    ///
    /// - Pseudo-Mersenne primes (top 64 bits all ones): `r = 2^k - q`, small.
    /// - Byte-aligned primes: `r = -floor(2^(2k) / q)`, a Barrett reciprocal.
    /// - Otherwise `None` — callers fall back to a generic remainder.
    ///
    /// Called once by the curve at construction; `r` only affects the speed of
    /// reduction, never the result.
    pub(crate) fn calculate_residue(q: &BigInteger) -> Option<BigInteger> {
        let bit_length = q.bit_length();
        if bit_length >= 96 {
            let one = BigInteger::from_u32(1);
            // 取 q 頂端 64 個位元。
            let first_word = q >> (bit_length - 64);
            let u64_max = &(&one << 64) - &one;
            if first_word == u64_max {
                // pseudo-Mersenne：q 頂端 64 位元全為 1，r = 2^k − q（小）。
                return Some(&(&one << bit_length) - q);
            }
            if bit_length & 7 == 0 {
                // byte 對齊長度：r = −⌊2^(2k) / q⌋（Barrett 倒數，負值）。
                return Some(-&(&(&one << (bit_length << 1)) / q));
            }
        }
        None
    }

    /// Returns the field modulus `q` (the prime p).
    pub fn q(&self) -> &BigInteger {
        &self.q
    }

    /// Returns the field size in bits, i.e. the bit length of `q`.
    ///
    /// Corresponds to `FieldSize` in Bouncy Castle.
    pub fn field_size(&self) -> u32 {
        self.q.bit_length()
    }

    /// Returns `true` if this element is the additive identity (zero).
    pub fn is_zero(&self) -> bool {
        self.x.is_zero()
    }

    /// Returns `true` if this element is the multiplicative identity (one).
    ///
    /// Mirrors Bouncy Castle's `IsOne => BitLength == 1`: only the value 1 has a
    /// bit length of exactly 1 (given the invariant `x >= 0`), so no comparison
    /// value needs to be allocated.
    pub fn is_one(&self) -> bool {
        self.x.bit_length() == 1
    }

    /// Returns `self + 1` in the field.
    ///
    /// Corresponds to `AddOne` in Bouncy Castle. Fast path: since `x < q`, the
    /// sum is at most `q`, so the only reduction needed is mapping `q` back to
    /// `0` — no general modular reduction.
    pub fn add_one(&self) -> Self {
        let x2 = &self.x + &BigInteger::from_u32(1);
        // x < q ⇒ x+1 ≤ q；唯一環繞是 x+1 == q → 0。
        let x2 = if x2 == self.q {
            BigInteger::from_u32(0)
        } else {
            x2
        };
        self.with_value(x2)
    }

    // TODO(ec-fp)：以下運算待實作（對應 bc FpFieldElement），全部 mod q：
    //   add / subtract / multiply / divide(= self × b⁻¹) / negate(q − x) /
    //   square / invert(mod_inverse) / sqrt(Tonelli–Shanks，依 q mod 4/8 分支)。
    //   乘法/平方的約簡走 mod_reduce（屆時才使用上面的 r 做 pseudo-Mersenne /
    //   Barrett 快速路徑，None 時退回通用取模）。
    // 約定：均為 &self、回傳新元素；兩運算元須同 q（debug_assert）。
}

/// Borrows the element's value as an integer in `[0, q)`.
///
/// The trait form of Bouncy Castle's `ToBigInteger()`; clone at the call site if
/// an owned copy is needed.
impl AsRef<BigInteger> for FpFieldElement {
    fn as_ref(&self) -> &BigInteger {
        &self.x
    }
}

/// Field addition: `(x + b.x) mod q`.
///
/// Corresponds to `Add` in Bouncy Castle (`ModAdd`). Both operands must belong
/// to the same field.
impl Add for &FpFieldElement {
    type Output = FpFieldElement;

    fn add(self, rhs: &FpFieldElement) -> FpFieldElement {
        debug_assert!(self.q == rhs.q, "add: field elements from different fields");
        // 不變式 0 ≤ x, rhs.x < q ⇒ 和 < 2q，最多減一次 q 即回到 [0, q)，
        // 不必整除取模（bc ModAdd 的做法）。
        let mut sum = &self.x + &rhs.x;
        if sum >= self.q {
            sum = &sum - &self.q;
        }
        self.with_value(sum)
    }
}

/// Field subtraction: `(x - b.x) mod q`.
///
/// Corresponds to `Subtract` in Bouncy Castle (`ModSubtract`). Both operands
/// must belong to the same field.
impl Sub for &FpFieldElement {
    type Output = FpFieldElement;

    fn sub(self, rhs: &FpFieldElement) -> FpFieldElement {
        debug_assert!(self.q == rhs.q, "sub: field elements from different fields");
        // 不變式 0 ≤ x, rhs.x < q ⇒ 差 ∈ (−q, q)；為負時加一次 q 回到 [0, q)。
        let mut diff = &self.x - &rhs.x;
        if diff.sign() < 0 {
            diff = &diff + &self.q;
        }
        self.with_value(diff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 測試輔助：模擬未來曲線建 element（算好 r 再傳入）。
    fn field_element(q: BigInteger, x: BigInteger) -> FpFieldElement {
        let r = FpFieldElement::calculate_residue(&q);
        FpFieldElement::new(q, x, r)
    }

    #[test]
    fn accessors_report_field() {
        let fe = field_element(BigInteger::from_u32(23), BigInteger::from_u32(1));
        assert_eq!(fe.field_size(), 5); // 23 = 0b10111，5 位元
        assert!(fe.is_one());
        assert!(!fe.is_zero());
    }

    #[test]
    fn residue_secp256k1_pseudo_mersenne() {
        // secp256k1 質數 p = 2^256 − 2^32 − 977，頂端 64 位元全為 1。
        let p = BigInteger::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        // r = 2^256 − p = 2^32 + 977 = 4294968273。
        let r = FpFieldElement::calculate_residue(&p);
        assert_eq!(r, Some(BigInteger::from_u64(4_294_968_273)));
    }

    #[test]
    fn add_wraps_modulo_q() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(5));
        let b = field_element(q.clone(), BigInteger::from_u32(4));
        // 5 + 4 = 9 ≡ 2 (mod 7)。
        assert_eq!((&a + &b).as_ref(), &BigInteger::from_u32(2));
        // 加 0 為單位元。
        let zero = field_element(q, BigInteger::from_u32(0));
        assert_eq!((&a + &zero).as_ref(), &BigInteger::from_u32(5));
    }

    #[test]
    fn sub_borrows_modulo_q() {
        let q = BigInteger::from_u32(7);
        let a = field_element(q.clone(), BigInteger::from_u32(3));
        let b = field_element(q.clone(), BigInteger::from_u32(5));
        // 3 − 5 = −2 ≡ 5 (mod 7)。
        assert_eq!((&a - &b).as_ref(), &BigInteger::from_u32(5));
        // 無借位情形：5 − 3 = 2。
        assert_eq!((&b - &a).as_ref(), &BigInteger::from_u32(2));
    }

    #[test]
    fn add_one_wraps_at_q() {
        let q = BigInteger::from_u32(7);
        // 一般情形：3 + 1 = 4。
        let a = field_element(q.clone(), BigInteger::from_u32(3));
        assert_eq!(a.add_one().as_ref(), &BigInteger::from_u32(4));
        // 環繞：q−1 加一 → 0。
        let top = field_element(q, BigInteger::from_u32(6));
        assert!(top.add_one().is_zero());
    }

    #[test]
    fn residue_small_prime_is_none() {
        // 位元長度 < 96 → 無快速形式。
        assert!(FpFieldElement::calculate_residue(&BigInteger::from_u32(97)).is_none());
    }
}
