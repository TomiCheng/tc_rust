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
#[derive(Clone, Debug)]
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

    /// Returns `true` if this is the additive identity (zero). Constant-time in the
    /// value. Corresponds to `IsZero` in bc.
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    /// Returns `true` if this is the multiplicative identity (one). Constant-time in
    /// the value. Corresponds to `IsOne` in bc.
    pub fn is_one(&self) -> bool {
        self.value.is_one()
    }

    /// **Variable-time** bit length of the value — polynomial degree + 1, or `0` for
    /// zero. Corresponds to `BitLength` in bc.
    pub fn bit_length(&self) -> usize {
        self.value.bit_length()
    }

    /// The field size in bits, i.e. the degree `m`. Corresponds to `FieldSize` in bc.
    //
    // 回 usize（對齊 m/bit_length）；FpFieldElement::field_size 回 u32。兩者統一留到
    // 之後抽 ECFieldElement trait 時再議。
    pub fn field_size(&self) -> usize {
        self.field.m()
    }

    /// Returns whether the constant term (the `x⁰` coefficient) is set. Corresponds
    /// to `TestBitZero` in bc (`x[0] & 1`). The field degree is `>= 1`, so there is
    /// always a limb 0.
    pub fn test_bit_zero(&self) -> bool {
        self.value.limbs()[0] & 1 == 1
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

    /// Returns the square root of this element.
    ///
    /// Corresponds to `Sqrt` in bc. In `GF(2ᵐ)` the Frobenius map `y ↦ y²` is a
    /// bijection, so every element has a **unique** square root — hence this returns
    /// `Self`, not `Option` (unlike the Fp field). The root is `self^(2^(m-1))`,
    /// since `(a^(2^(m-1)))² = a^(2ᵐ) = a`. bc fast-paths `0`/`1` (`BitLength <= 1`).
    pub fn sqrt(&self) -> Self {
        if self.value.bit_length() <= 1 {
            return self.clone(); // √0 = 0、√1 = 1
        }
        self.square_pow(self.field.m() - 1)
    }

    /// Returns `self·b + x·y` in the field. Corresponds to `MultiplyPlusProduct` (bc's
    /// base default). Unlike the Fp field there is no fused single-reduction — F2m
    /// `multiply` already reduces — so this is just two products XOR-ed.
    pub fn multiply_plus_product(&self, b: &Self, x: &Self, y: &Self) -> Self {
        &(self * b) + &(x * y)
    }

    /// Returns `self·b − x·y`. In characteristic 2, `−v == v`, so this **equals**
    /// [`multiply_plus_product`](Self::multiply_plus_product). Corresponds to bc's
    /// `MultiplyMinusProduct` override (`=> MultiplyPlusProduct`).
    pub fn multiply_minus_product(&self, b: &Self, x: &Self, y: &Self) -> Self {
        self.multiply_plus_product(b, x, y)
    }

    /// Returns `self² + x·y` in the field. Corresponds to `SquarePlusProduct` (bc's
    /// base default).
    pub fn square_plus_product(&self, x: &Self, y: &Self) -> Self {
        &self.square() + &(x * y)
    }

    /// Returns `self² − x·y`. In characteristic 2 this **equals**
    /// [`square_plus_product`](Self::square_plus_product). Corresponds to bc's
    /// `SquareMinusProduct` override.
    pub fn square_minus_product(&self, x: &Self, y: &Self) -> Self {
        self.square_plus_product(x, y)
    }

    // TODO(ec-f2m)：以下待點層（F2mCurve/F2mPoint、SEC 點編解碼）真的用到時再補：
    //   - to_big_integer()：對齊 bc `Nat.ToBigInteger64(x)`。需先補「u64 limbs →
    //     BigInteger」這條路（現 BigInteger magnitude 是 u32、big-endian、去前導零）。
    //     座標序列化與 ToBigInteger() 會用到。
    //   - trace() / half_trace()（AbstractF2mFieldElement）：點解壓縮解 `y²+y = x`
    //     二次方程用；為平方+加的加法鏈（bc 有 log 步版本，非樸素 O(m)）。
    //   - get_encoded()/encode_to()（ECFieldElement 基底）：SEC 壓縮點格式，
    //     BinaryPoly → 定長 big-endian bytes。
    //   - X9.62 metadata accessor：m()/k1()/k2()/k3()/representation()（Tpb/Ppb）、
    //     field_name()="F2m"，對外委派 field；曲線/ASN.1 序列化用。
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

/// Two elements are equal iff they share the same field and value.
///
/// Corresponds to bc's `Equals`. The field is compared first (by degree + reduction
/// polynomial); only then — when the limb counts are known to match — is the value
/// compared with the constant-time [`BinaryPoly::ct_eq`], matching bc's use of
/// `BinPolys.EqualTo`.
impl PartialEq for F2mFieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.value.ct_eq(&other.value)
    }
}

impl Eq for F2mFieldElement {}

/// Hashes the value limbs and the field (matching [`PartialEq`]).
///
/// Corresponds to bc `GetHashCode` (`hash(x) ^ hash(f2mFieldData)`).
impl core::hash::Hash for F2mFieldElement {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.value.limbs().hash(state);
        self.field.hash(state);
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
// clippy 的 suspicious_arithmetic_impl 會警告「Sub 裡用了 +」——此處是 char 2 的
// 刻意等式（減即加），非筆誤。
#[allow(clippy::suspicious_arithmetic_impl)]
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

    #[test]
    fn queries_report_value_and_field() {
        let f = field16();
        let zero = fe(&f, 0);
        let one = fe(&f, 1);
        let a = fe(&f, 0b1010); // x^3 + x

        assert!(zero.is_zero() && !zero.is_one());
        assert!(one.is_one() && !one.is_zero());

        assert_eq!(zero.bit_length(), 0);
        assert_eq!(one.bit_length(), 1);
        assert_eq!(a.bit_length(), 4); // 最高次 x^3 → degree 3 → 長度 4

        assert_eq!(a.field_size(), 4); // GF(2^4)

        assert!(!a.test_bit_zero()); // x^3+x：常數項 0
        assert!(fe(&f, 0b1011).test_bit_zero()); // x^3+x+1：常數項 1
    }

    #[test]
    fn sqrt_is_inverse_of_square() {
        let f = field16();
        assert!(fe(&f, 0).sqrt().is_zero()); // √0 = 0
        assert!(fe(&f, 1).sqrt().is_one()); // √1 = 1
        // 每個元素平方根唯一且必存在：√a 的平方等於 a
        for v in 0u64..16 {
            let a = fe(&f, v);
            assert_eq!(a.sqrt().square(), a, "v={v}");
        }
    }

    #[test]
    fn eq_and_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        fn h(e: &F2mFieldElement) -> u64 {
            let mut s = DefaultHasher::new();
            e.hash(&mut s);
            s.finish()
        }

        let f = field16();
        let a = fe(&f, 0b1011);
        let b = fe(&f, 0b1011);
        let c = fe(&f, 0b1100);
        // 同體域同值 → 相等且 hash 相等。
        assert_eq!(a, b);
        assert_eq!(h(&a), h(&b));
        // 同體域不同值 → 不相等。
        assert_ne!(a, c);
        // 不同體域 → 不相等（field 先比即短路，不會走到不同 size 的 ct_eq）。
        let g = Arc::new(F2mField::pentanomial(163, 3, 6, 7));
        let other = F2mFieldElement::new(Arc::clone(&g), BinaryPoly::zero(g.size()));
        assert_ne!(a, other);
    }

    #[test]
    fn fused_products_match_naive() {
        let f = field16();
        let a = fe(&f, 0b1011);
        let b = fe(&f, 0b0110);
        let x = fe(&f, 0b0101);
        let y = fe(&f, 0b1110);
        // fused == 樸素兩次乘再加
        assert_eq!(a.multiply_plus_product(&b, &x, &y), &(&a * &b) + &(&x * &y));
        assert_eq!(a.square_plus_product(&x, &y), &a.square() + &(&x * &y));
        // char 2：minus == plus
        assert_eq!(a.multiply_minus_product(&b, &x, &y), a.multiply_plus_product(&b, &x, &y));
        assert_eq!(a.square_minus_product(&x, &y), a.square_plus_product(&x, &y));
    }
}

