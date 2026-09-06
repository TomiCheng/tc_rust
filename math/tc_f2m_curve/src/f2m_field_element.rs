//! 二元擴張體元素。
//!
//! 元素只知道共享的 [`F2mField`] 與泛型多項式值 `P`；配置版與固定寬度版
//! 因而共用完全相同的 EC 體域公式，差異只留在 `tc_binpoly` 的值表示內。

use alloc::{sync::Arc, vec};
use core::ops::{Add, Div, Mul, Neg, Sub};

use tc_binpoly::{
    BinaryPoly, BinaryPolyOps, STACK_ALLOC_CUTOFF, bit_length_var, equal_to_one, equal_to_zero,
};

use crate::{F2mField, F2mInteger, F2mPolynomial};

/// `GF(2^m)` 的 polynomial-basis 元素。
#[derive(Clone)]
pub struct F2mFieldElement<P: BinaryPolyOps = BinaryPoly> {
    field: Arc<F2mField>,
    value: P,
}

impl<P: BinaryPolyOps> F2mFieldElement<P> {
    pub(crate) fn new(field: Arc<F2mField>, value: P) -> Self {
        debug_assert_eq!(value.multiplier(), field.multiplier());
        debug_assert_eq!(value.as_limbs().len(), field.size());
        Self { field, value }
    }

    fn with_value(&self, value: P) -> Self {
        Self {
            field: Arc::clone(&self.field),
            value,
        }
    }

    /// 此元素所屬的共享體域。
    pub fn field(&self) -> &Arc<F2mField> {
        &self.field
    }

    /// 底層二進位多項式值。
    pub fn value(&self) -> &P {
        &self.value
    }

    /// 是否為加法單位元。
    pub fn is_zero(&self) -> bool {
        equal_to_zero(self.value.as_limbs()) == u64::MAX
    }

    /// 是否為乘法單位元。
    pub fn is_one(&self) -> bool {
        equal_to_one(self.value.as_limbs()) == u64::MAX
    }

    /// 變動時間的有效位元長度。
    pub fn bit_length(&self) -> usize {
        bit_length_var(self.value.as_limbs())
    }

    /// 體域度數 `m`。
    pub fn field_size(&self) -> usize {
        self.field.m()
    }

    /// 常數項是否為一。
    pub fn test_bit_zero(&self) -> bool {
        self.value.as_limbs()[0] & 1 == 1
    }

    /// 將 polynomial-basis bits 解讀成指定的非負整數型別。
    pub fn to_integer<B: F2mInteger>(&self) -> B {
        match B::from_le_u64(self.value.as_limbs()) {
            Ok(value) => value,
            Err(_) => panic!("F2m field element does not fit the selected integer type"),
        }
    }

    /// 回傳同一個體域中的零。
    pub fn zero(&self) -> Self {
        self.with_value(
            P::zero(self.field.multiplier().clone())
                .expect("field and polynomial width were checked at construction"),
        )
    }

    /// 回傳同一個體域中的一。
    pub fn one(&self) -> Self {
        self.with_value(
            P::one(self.field.multiplier().clone())
                .expect("field and polynomial width were checked at construction"),
        )
    }

    /// 加上一，亦即翻轉常數項。
    pub fn add_one(&self) -> Self {
        self.with_value(self.value.clone() + &self.one().value)
    }

    /// 體域平方。
    pub fn square(&self) -> Self {
        self.with_value(self.value.square())
    }

    /// 計算 `self^(2^count)`。
    pub fn square_pow(&self, count: usize) -> Self {
        self.with_value(self.value.square_pow(count))
    }

    /// 體域反元素；沿用 BC 慣例讓零映到零。
    pub fn invert(&self) -> Self {
        if self.bit_length() <= 1 {
            return self.clone();
        }
        self.with_value(
            self.value
                .invert()
                .expect("F2m fields use an invertible trinomial or pentanomial"),
        )
    }

    /// `GF(2^m)` 中唯一的平方根。
    pub fn sqrt(&self) -> Self {
        if self.bit_length() <= 1 {
            return self.clone();
        }
        self.square_pow(self.field.m() - 1)
    }

    /// 計算 `self * b + x * y`。
    pub fn multiply_plus_product(&self, b: &Self, x: &Self, y: &Self) -> Self {
        &(self * b) + &(x * y)
    }

    /// 特徵二下減法等於加法。
    pub fn multiply_minus_product(&self, b: &Self, x: &Self, y: &Self) -> Self {
        self.multiply_plus_product(b, x, y)
    }

    /// 計算 `self^2 + x * y`。
    pub fn square_plus_product(&self, x: &Self, y: &Self) -> Self {
        &self.square() + &(x * y)
    }

    /// 特徵二下減法等於加法。
    pub fn square_minus_product(&self, x: &Self, y: &Self) -> Self {
        self.square_plus_product(x, y)
    }

    /// 絕對 trace，結果只會是零或一。
    pub fn trace(&self) -> u8 {
        let m = self.field.m();
        let mut k = m.ilog2() as usize;
        let mut mk = 1_usize;
        let mut trace = self.clone();
        while k > 0 {
            trace = &trace.square_pow(mk) + &trace;
            k -= 1;
            mk = m >> k;
            if mk & 1 != 0 {
                trace = &trace.square() + self;
            }
        }
        if trace.is_zero() {
            0
        } else if trace.is_one() {
            1
        } else {
            panic!("trace result must lie in GF(2)")
        }
    }

    /// 奇數次擴張體的 half-trace。
    pub fn half_trace(&self) -> Self {
        let m = self.field.m();
        assert!(m & 1 == 1, "half_trace is only defined for odd m");
        let n = (m + 1) >> 1;
        let mut k = n.ilog2() as usize;
        let mut nk = 1_usize;
        let mut half_trace = self.clone();
        while k > 0 {
            half_trace = &half_trace.square_pow(nk << 1) + &half_trace;
            k -= 1;
            nk = n >> k;
            if nk & 1 != 0 {
                half_trace = &half_trace.square_pow(2) + self;
            }
        }
        half_trace
    }
}

impl<P: F2mPolynomial> F2mFieldElement<P> {
    pub(crate) fn from_integer<B: F2mInteger>(field: Arc<F2mField>, value: &B) -> Self {
        assert!(
            value.bit_length() <= field.m(),
            "value invalid for F2m field element"
        );

        // 固定整數會輸出完整寬度（例如 U256 是 4 limbs），可能大於 sect163
        // 元素的 3 limbs；緩衝取兩者較大值，驗證高位為零後再交給多項式。
        let required = field.size().max(value.u64_length());
        if required <= STACK_ALLOC_CUTOFF {
            let mut limbs = [0_u64; STACK_ALLOC_CUTOFF];
            return Self::from_integer_limbs(field, value, &mut limbs[..required]);
        }

        let mut limbs = vec![0_u64; required];
        Self::from_integer_limbs(field, value, &mut limbs)
    }

    fn from_integer_limbs<B: F2mInteger>(
        field: Arc<F2mField>,
        value: &B,
        limbs: &mut [u64],
    ) -> Self {
        let written = value
            .write_le_u64(limbs)
            .expect("buffer includes the integer's complete limb width");
        assert!(
            written <= field.size() || limbs[field.size()..written].iter().all(|limb| *limb == 0),
            "value invalid for F2m field element"
        );
        let value = P::from_limb_slice(field.multiplier().clone(), &limbs[..field.size()])
            .expect("polynomial width must match the selected F2m field");
        Self::new(field, value)
    }
}

impl<P: BinaryPolyOps> PartialEq for F2mFieldElement<P> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.value == other.value
    }
}

impl<P: BinaryPolyOps> Eq for F2mFieldElement<P> {}

impl<P: BinaryPolyOps> core::fmt::Debug for F2mFieldElement<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("F2mFieldElement")
            .field("m", &self.field.m())
            .field("limbs", &self.value.as_limbs())
            .finish()
    }
}

impl<P: BinaryPolyOps> core::hash::Hash for F2mFieldElement<P> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.field.hash(state);
        self.value.as_limbs().hash(state);
    }
}

impl<P: BinaryPolyOps> Add for &F2mFieldElement<P> {
    type Output = F2mFieldElement<P>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.field, rhs.field);
        self.with_value(self.value.clone() + &rhs.value)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<P: BinaryPolyOps> Sub for &F2mFieldElement<P> {
    type Output = F2mFieldElement<P>;

    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl<P: BinaryPolyOps> Mul for &F2mFieldElement<P> {
    type Output = F2mFieldElement<P>;

    fn mul(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.field, rhs.field);
        self.with_value(
            self.value
                .multiply(&rhs.value)
                .expect("field elements share one reduction polynomial"),
        )
    }
}

// 體域除法的定義就是乘上反元素；這不是把整數乘法誤寫進除法。
#[allow(clippy::suspicious_arithmetic_impl)]
impl<P: BinaryPolyOps> Div for &F2mFieldElement<P> {
    type Output = F2mFieldElement<P>;

    fn div(self, rhs: Self) -> Self::Output {
        self * &rhs.invert()
    }
}

impl<P: BinaryPolyOps> Neg for &F2mFieldElement<P> {
    type Output = F2mFieldElement<P>;

    fn neg(self) -> Self::Output {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tc_bigint::{BigUint, U256};
    use tc_binpoly::FixedBinaryPoly;

    fn exercise<P: F2mPolynomial, B: F2mInteger>() {
        let field = Arc::new(F2mField::trinomial(5, 2).unwrap());
        let integer = match B::from_unsigned_le_bytes(&[0b1_1011]) {
            Ok(value) => value,
            Err(_) => panic!("test value fits the selected integer type"),
        };
        let element = F2mFieldElement::<P>::from_integer(Arc::clone(&field), &integer);
        assert!(element.to_integer::<B>() == integer);
        assert_eq!(element.sqrt().square(), element);
        assert_eq!(&element * &element.invert(), element.one());
        assert_eq!(element.square(), &element * &element);
        assert!(matches!(element.trace(), 0 | 1));

        let beta = &element.square() + &element;
        let root = beta.half_trace();
        assert_eq!(&root.square() + &root, beta);
    }

    #[test]
    fn dynamic_and_fixed_values_share_field_formulas() {
        exercise::<BinaryPoly, BigUint>();
        exercise::<FixedBinaryPoly<1>, U256>();
    }
}
