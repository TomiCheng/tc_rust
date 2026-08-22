//! Binary-field elements for elliptic curves.
//!
//! Corresponds to `F2mFieldElement` in Bouncy Castle C#: an element of `GF(2ᵐ)` in
//! polynomial basis. Unlike [`FpFieldElement`], which carries its modulus by value,
//! an F2m element holds an `Arc<F2mField>` — the field's multiply/invert operators
//! are non-cloneable trait objects, so a whole curve's elements share one definition.
//!
//! [`FpFieldElement`]: super::FpFieldElement

use alloc::sync::Arc;
use core::ops::{Add, Div, Mul, Neg, Sub};

use crate::binpoly::BinaryPoly;
use crate::ec::f2m_field::F2mField;

/// An element of the binary field `GF(2ᵐ)` in polynomial basis.
///
/// The value is a [`BinaryPoly`] of `field.size()` limbs (degree `< m`, zero-padded);
/// the shared [`F2mField`] supplies the arithmetic operators. Mirrors bc
/// `F2mFieldElement`.
#[derive(Clone)]
pub struct F2mFieldElement {
    // 共享的體域定義（m + 約簡多項式 + mul/inv operator）。
    field: Arc<F2mField>,
    // 元素值：field.size() 個 u64 limb，degree < m、補零。
    value: BinaryPoly,
}

impl F2mFieldElement {
    /// Low-level constructor mirroring bc's internal `F2mFieldElement(f2mFieldData, x)`:
    /// stores the value directly. The caller (the curve) supplies a value already
    /// reduced to degree `< m` in `field.size()` limbs.
    ///
    /// Crate-internal (bc marks it `internal`); external callers build field elements
    /// through the curve.
    pub(crate) fn new(field: Arc<F2mField>, value: BinaryPoly) -> Self {
        debug_assert_eq!(value.size(), field.size(), "value limb count must match the field");
        F2mFieldElement { field, value }
    }

    /// Creates a new element in the same field (sharing the `Arc<F2mField>`) holding
    /// `value`. Corresponds to the `new F2mFieldElement(f2mFieldData, z)` pattern
    /// bc uses throughout its arithmetic.
    fn with_value(&self, value: BinaryPoly) -> Self {
        F2mFieldElement { field: Arc::clone(&self.field), value }
    }

    /// Returns `self + 1` in the field, i.e. flips the constant term.
    ///
    /// Corresponds to `AddOne` in bc (`z[0] ^= 1`). Adding the polynomial `1` (low
    /// bit set) toggles only the `x⁰` coefficient.
    pub fn add_one(&self) -> Self {
        let one = BinaryPoly::one(self.field.size());
        self.with_value(&self.value + &one)
    }

    /// Returns `self²` in the field. Corresponds to `Square` in bc.
    pub fn square(&self) -> Self {
        self.with_value(self.value.square(self.field.mul()))
    }

    /// Returns `self^(2^pow)` — `pow` repeated squarings (the Frobenius power).
    /// `pow == 0` returns `self` unchanged. Corresponds to `SquarePow` in bc.
    pub fn square_pow(&self, pow: usize) -> Self {
        self.with_value(self.value.square_pow(pow, self.field.mul()))
    }

    /// Returns the multiplicative inverse `self⁻¹` in the field.
    ///
    /// Corresponds to `Invert` in bc. `0` and `1` are their own inverses; bc takes a
    /// fast path for them (`BitLength <= 1`) out of the otherwise value-independent
    /// Itoh–Tsujii computation.
    pub fn invert(&self) -> Self {
        if self.value.bit_length() <= 1 {
            return self.clone(); // 0⁻¹ = 0、1⁻¹ = 1，避開完整反元素計算
        }
        self.with_value(self.value.invert(self.field.inv()))
    }
}

/// Field multiplication `self · rhs mod r(x)`, delegated to the field's multiply
/// operator. Corresponds to `Multiply` in bc. Both operands must share the field.
impl Mul for &F2mFieldElement {
    type Output = F2mFieldElement;

    fn mul(self, rhs: &F2mFieldElement) -> F2mFieldElement {
        debug_assert!(self.field == rhs.field, "mul: elements from different fields");
        self.with_value(self.value.multiply(&rhs.value, self.field.mul()))
    }
}

/// Field division `self · rhs⁻¹`. Corresponds to `Divide` in bc
/// (`Multiply(b.Invert())`).
///
/// By the F2m convention `0⁻¹ = 0`, dividing by zero yields zero rather than
/// panicking (unlike the Fp field); callers must ensure `rhs` is non-zero for a
/// meaningful result.
impl Div for &F2mFieldElement {
    type Output = F2mFieldElement;

    fn div(self, rhs: &F2mFieldElement) -> F2mFieldElement {
        debug_assert!(self.field == rhs.field, "div: elements from different fields");
        self * &rhs.invert()
    }
}

/// Field addition over `GF(2ᵐ)`: coefficient-wise XOR (no carry, no reduction —
/// degree-`< m` inputs stay degree-`< m`).
///
/// Corresponds to `Add` in bc. Both operands must belong to the same field.
impl Add for &F2mFieldElement {
    type Output = F2mFieldElement;

    fn add(self, rhs: &F2mFieldElement) -> F2mFieldElement {
        debug_assert!(self.field == rhs.field, "add: elements from different fields");
        self.with_value(&self.value + &rhs.value)
    }
}

/// Field subtraction. In characteristic 2, `−b == b`, so subtraction **is** addition.
///
/// Corresponds to `Subtract` in bc (`=> Add(b)`).
impl Sub for &F2mFieldElement {
    type Output = F2mFieldElement;

    fn sub(self, rhs: &F2mFieldElement) -> F2mFieldElement {
        self + rhs
    }
}

/// Field negation. In characteristic 2, every element is its own additive inverse
/// (`x + x = 0`), so `−x == x`.
///
/// Corresponds to `Negate` in bc (`=> this`). bc returns the same instance; we
/// return a cheap clone (shared `Arc` field + cloned value).
impl Neg for &F2mFieldElement {
    type Output = F2mFieldElement;

    fn neg(self) -> F2mFieldElement {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // GF(2^4) = GF(2)[x] / (x^4 + x + 1)：size 1 limb，加法測試不依賴約簡形狀。
    fn field16() -> Arc<F2mField> {
        Arc::new(F2mField::trinomial(4, 1))
    }

    fn fe(field: &Arc<F2mField>, v: u64) -> F2mFieldElement {
        F2mFieldElement::new(Arc::clone(field), BinaryPoly::from_limbs([v]))
    }

    #[test]
    fn add_is_xor() {
        let f = field16();
        // (x^3+x+1) + (x^2+x) = x^3+x^2+1
        let a = fe(&f, 0b1011);
        let b = fe(&f, 0b0110);
        assert_eq!((&a + &b).value.limbs(), &[0b1101]);
    }

    #[test]
    fn add_is_self_inverse() {
        let f = field16();
        let a = fe(&f, 0b1011);
        // 二元體：a + a = 0
        assert!((&a + &a).value.is_zero());
    }

    #[test]
    fn subtract_equals_add() {
        let f = field16();
        let a = fe(&f, 0b1011);
        let b = fe(&f, 0b0110);
        assert_eq!((&a - &b).value.limbs(), (&a + &b).value.limbs());
    }

    #[test]
    fn negate_is_identity() {
        let f = field16();
        let a = fe(&f, 0b1011);
        // −x == x
        assert_eq!((-&a).value.limbs(), a.value.limbs());
        // a + (−a) = 0
        assert!((&a + &(-&a)).value.is_zero());
    }

    #[test]
    fn add_one_flips_constant_term() {
        let f = field16();
        // (x^3+x) + 1 = x^3+x+1
        assert_eq!(fe(&f, 0b1010).add_one().value.limbs(), &[0b1011]);
        // 常數項已是 1 → 清掉：(x+1) + 1 = x
        assert_eq!(fe(&f, 0b0011).add_one().value.limbs(), &[0b0010]);
    }

    #[test]
    fn multiply_reduces_mod_poly() {
        let f = field16();
        // x^3 · x = x^4 ≡ x + 1（x^4 ≡ x+1）
        assert_eq!((&fe(&f, 0b1000) * &fe(&f, 0b0010)).value.limbs(), &[0b0011]);
        // a · 1 = a
        assert_eq!((&fe(&f, 0b0111) * &fe(&f, 0b0001)).value.limbs(), &[0b0111]);
    }

    #[test]
    fn square_matches_self_multiply() {
        let f = field16();
        let a = fe(&f, 0b0101); // x^2 + 1
        // (x^2+1)^2 = x^4 + 1 ≡ (x+1) + 1 = x
        assert_eq!(a.square().value.limbs(), &[0b0010]);
        assert_eq!(a.square().value.limbs(), (&a * &a).value.limbs());
    }

    #[test]
    fn square_pow_iterates() {
        let f = field16();
        let a = fe(&f, 0b1101);
        assert_eq!(a.square_pow(0).value.limbs(), a.value.limbs()); // pow 0 → self
        assert_eq!(a.square_pow(2).value.limbs(), a.square().square().value.limbs());
    }

    #[test]
    fn invert_is_multiplicative_inverse() {
        let f = field16();
        // 0⁻¹ = 0、1⁻¹ = 1（快速路徑）
        assert!(fe(&f, 0).invert().value.is_zero());
        assert!(fe(&f, 1).invert().value.is_one());
        // 非零 a：a · a⁻¹ = 1
        for v in 1u64..16 {
            let a = fe(&f, v);
            assert!((&a * &a.invert()).value.is_one(), "v={v}");
        }
    }

    #[test]
    fn divide_is_multiply_by_inverse() {
        let f = field16();
        let a = fe(&f, 0b0111);
        let b = fe(&f, 0b0011);
        // (a / b) · b = a
        assert_eq!((&(&a / &b) * &b).value.limbs(), a.value.limbs());
    }
}

