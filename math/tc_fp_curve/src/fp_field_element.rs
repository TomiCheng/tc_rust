//! 以 Montgomery domain 表示的質數體元素。
//!
//! 體域整數由 [`FpInteger`] 決定；共享的 [`FpField`] 保存質數與 Montgomery
//! 參數，元素永遠代表 `[0, q)`，不需要舊版帶符號 `BigInt` 的修正分支。

use alloc::sync::Arc;
use core::ops::{Add, Div, Mul, Neg, Sub};
#[cfg(feature = "bench-internals")]
use core::sync::atomic::{AtomicUsize, Ordering};

use tc_bigint::modular::Monty;
use tc_bigint::{BigUint, Odd};

use crate::FpInteger;
use tc_bigint::{
    Choice, ConditionallySelectable, ConstantTimeEq, FixedBigUint, modular::FixedMontyForm,
};
use tc_ec_core::SecretField;

impl<const N: usize> ConditionallySelectable for FpFieldElement<FixedBigUint<N>> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        a.with_monty(FixedMontyForm::conditional_select(
            &a.value, &b.value, choice,
        ))
    }
}
impl<const N: usize> ConstantTimeEq for FpFieldElement<FixedBigUint<N>> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.value.ct_eq(&rhs.value)
    }
}
impl<const N: usize> SecretField for FpFieldElement<FixedBigUint<N>> {
    fn ct_zero(&self) -> Self {
        self.with_monty(FixedMontyForm::zero(*self.value.params()))
    }
    fn ct_one(&self) -> Self {
        self.with_monty(FixedMontyForm::one(*self.value.params()))
    }
    fn ct_add(&self, rhs: &Self) -> Self {
        self.with_monty(self.value + rhs.value)
    }
    fn ct_sub(&self, rhs: &Self) -> Self {
        self.with_monty(self.value - rhs.value)
    }
    fn ct_mul(&self, rhs: &Self) -> Self {
        self.with_monty(self.value * rhs.value)
    }
    fn ct_square(&self) -> Self {
        self.with_monty(self.value.square())
    }
    fn ct_invert(&self) -> Self {
        let exponent = *self.q() - FixedBigUint::from(2_u8);
        self.with_monty(self.value.pow_ct(&exponent))
    }
}
impl<const N: usize> tc_ec_core::SecretCurve for crate::FpCurve<FixedBigUint<N>> {
    const BINARY: bool = false;
}

#[cfg(feature = "bench-internals")]
static INVERSION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 清除 benchmark 用的體域反元素計數器。
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn reset_inversion_count() {
    INVERSION_COUNT.store(0, Ordering::Relaxed);
}

/// 讀取 benchmark 用的體域反元素次數。
#[cfg(feature = "bench-internals")]
#[doc(hidden)]
pub fn inversion_count() -> usize {
    INVERSION_COUNT.load(Ordering::Relaxed)
}

/// 同一個 Fp 體域共用的 Montgomery 參數。
#[derive(Clone)]
pub(crate) struct FpField<B: FpInteger = BigUint> {
    params: <B::Monty as Monty>::Params,
    q: B,
}

impl<B: FpInteger> FpField<B> {
    pub(crate) fn new(q: B) -> Arc<Self> {
        let modulus = Odd::new(q.clone()).expect("curve prime is odd");
        Arc::new(Self {
            params: B::Monty::new_params_vartime(modulus),
            q,
        })
    }

    pub(crate) fn q(&self) -> &B {
        &self.q
    }

    pub(crate) fn element(self: &Arc<Self>, value: &B) -> FpFieldElement<B> {
        assert!(value < self.q(), "value invalid for Fp field element");
        FpFieldElement {
            field: Arc::clone(self),
            value: B::Monty::new(value, self.params.clone()),
        }
    }
}

impl<B: FpInteger> PartialEq for FpField<B> {
    fn eq(&self, other: &Self) -> bool {
        self.q == other.q
    }
}

impl<B: FpInteger> Eq for FpField<B> {}

impl<B: FpInteger> core::fmt::Debug for FpField<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpField").field("q", &self.q).finish()
    }
}

/// 質數體 `GF(q)` 的一個元素。
#[derive(Clone)]
pub struct FpFieldElement<B: FpInteger = BigUint> {
    field: Arc<FpField<B>>,
    value: B::Monty,
}

impl<B: FpInteger> FpFieldElement<B> {
    fn with_monty(&self, value: B::Monty) -> Self {
        Self {
            field: Arc::clone(&self.field),
            value,
        }
    }

    fn multiply(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.field, rhs.field, "different Fp fields");
        self.with_monty(self.value.clone() * &rhs.value)
    }

    /// 回傳體域質數 `q`。
    pub fn q(&self) -> &B {
        self.field.q()
    }

    /// 回傳 `q` 的有效位元數。
    pub fn field_size(&self) -> usize {
        self.q().bit_length()
    }

    /// 離開 Montgomery domain，回傳 `[0, q)` 的標準整數。
    pub fn to_big_uint(&self) -> B {
        self.value.retrieve()
    }

    /// 在同一個 Fp 體域中建立元素。
    pub fn element_from_big_uint(&self, value: &B) -> Self {
        self.field.element(value)
    }

    /// 同一體域的加法單位元。
    pub fn zero(&self) -> Self {
        self.with_monty(B::Monty::zero(self.value.params().clone()))
    }

    /// 同一體域的乘法單位元。
    pub fn one(&self) -> Self {
        self.with_monty(B::Monty::one(self.value.params().clone()))
    }

    /// 是否為零。
    pub fn is_zero(&self) -> bool {
        self.to_big_uint().is_zero()
    }

    /// 是否為一。
    pub fn is_one(&self) -> bool {
        self.to_big_uint().is_one()
    }

    /// 在 Montgomery domain 內平方。
    pub fn square(&self) -> Self {
        self.with_monty(self.value.square())
    }

    /// 在 Montgomery domain 內做公開指數次方。
    pub fn pow(&self, exponent: &B) -> Self {
        self.with_monty(self.value.pow(exponent))
    }

    /// 回傳乘法反元素；零或不可逆元素回傳 `None`。
    ///
    /// 具體反元素路徑由 `B::Monty` 決定；本層只保留 Montgomery 抽象。
    pub fn invert(&self) -> Option<Self> {
        #[cfg(feature = "bench-internals")]
        INVERSION_COUNT.fetch_add(1, Ordering::Relaxed);
        self.value.invert().map(|value| self.with_monty(value))
    }

    /// 回傳平方根；非二次剩餘時為 `None`。
    ///
    /// `q ≡ 3 (mod 4)` 與 `q ≡ 5 (mod 8)` 使用 BC 的直接公式；
    /// `q ≡ 1 (mod 8)` 使用 Lucas sequence。所有 modular power 都留在
    /// Montgomery domain。
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(self.clone());
        }

        let q = self.q();
        assert!(q.test_bit(0), "sqrt does not support an even modulus");
        let one_value = B::from_u8(1).expect("Fp integer represents one");

        if q.test_bit(1) {
            let exponent = (q.clone() >> 2) + &one_value;
            return self.check_sqrt(self.pow(&exponent));
        }

        if q.test_bit(2) {
            let t1 = self.pow(&(q.clone() >> 3));
            let t2 = &t1 * self;
            let t3 = &t2 * &t1;
            if t3.is_one() {
                return self.check_sqrt(t2);
            }
            let two_value = B::from_u8(2).expect("Fp integer represents two");
            let two = self.element_from_big_uint(&two_value);
            let t4 = two.pow(&(q.clone() >> 2));
            return self.check_sqrt(&t2 * &t4);
        }

        let legendre_exponent = q.clone() >> 1;
        if !self.pow(&legendre_exponent).is_one() {
            return None;
        }

        let two_x = self + self;
        let four_x = &two_x + &two_x;
        let k = legendre_exponent.clone() + &one_value;
        let q_minus_one_value = q.clone() - &one_value;
        let q_minus_one = self.element_from_big_uint(&q_minus_one_value);
        let mut p_value = one_value.clone();

        loop {
            if &p_value >= q {
                return None;
            }
            let p = self.element_from_big_uint(&p_value);
            let discriminant = &p.square() - &four_x;
            if discriminant.pow(&legendre_exponent) == q_minus_one {
                let (u, v) = self.lucas_sequence(&p, self, &k);
                if v.square() == four_x {
                    return Some(self.mod_half_abs(&v));
                }
                if !u.is_one() && u != q_minus_one {
                    return None;
                }
            }
            p_value = p_value + &one_value;
        }
    }

    fn check_sqrt(&self, candidate: Self) -> Option<Self> {
        (candidate.square() == *self).then_some(candidate)
    }

    fn mod_half_abs(&self, value: &Self) -> Self {
        let value = value.to_big_uint();
        let half = if value.test_bit(0) {
            (self.q().clone() - &value) >> 1
        } else {
            value >> 1
        };
        self.element_from_big_uint(&half)
    }

    fn lucas_sequence(&self, p: &Self, lucas_q: &Self, k: &B) -> (Self, Self) {
        let n = k.bit_length();
        let s = k
            .lowest_set_bit()
            .expect("lucas_sequence requires non-zero k");

        let mut uh = self.one();
        let two_value = B::from_u8(2).expect("Fp integer represents two");
        let mut vl = self.element_from_big_uint(&two_value);
        let mut vh = p.clone();
        let mut ql = self.one();
        let mut qh = self.one();

        let mut j = n - 1;
        while j > s {
            ql = &ql * &qh;
            if k.test_bit(j) {
                qh = &ql * lucas_q;
                uh = &uh * &vh;
                vl = &(&vh * &vl) - &(p * &ql);
                vh = &vh.square() - &(&qh + &qh);
            } else {
                qh = ql.clone();
                uh = &(&uh * &vl) - &ql;
                vh = &(&vh * &vl) - &(p * &ql);
                vl = &vl.square() - &(&ql + &ql);
            }
            j -= 1;
        }

        ql = &ql * &qh;
        qh = &ql * lucas_q;
        uh = &(&uh * &vl) - &ql;
        vl = &(&vh * &vl) - &(p * &ql);
        ql = &ql * &qh;

        for _ in 0..s {
            uh = &uh * &vl;
            vl = &vl.square() - &(&ql + &ql);
            ql = ql.square();
        }

        (uh, vl)
    }
}

impl<B: FpInteger> PartialEq for FpFieldElement<B> {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.value == other.value
    }
}

impl<B: FpInteger> Eq for FpFieldElement<B> {}

impl<B: FpInteger> core::fmt::Debug for FpFieldElement<B> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpFieldElement")
            .field("value", &self.to_big_uint())
            .field("q", self.q())
            .finish()
    }
}

impl<B: FpInteger> Add for &FpFieldElement<B> {
    type Output = FpFieldElement<B>;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.field, rhs.field, "different Fp fields");
        self.with_monty(self.value.clone() + &rhs.value)
    }
}

impl<B: FpInteger> Sub for &FpFieldElement<B> {
    type Output = FpFieldElement<B>;

    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.field, rhs.field, "different Fp fields");
        self.with_monty(self.value.clone() - &rhs.value)
    }
}

impl<B: FpInteger> Mul for &FpFieldElement<B> {
    type Output = FpFieldElement<B>;

    fn mul(self, rhs: Self) -> Self::Output {
        self.multiply(rhs)
    }
}

impl<B: FpInteger> Div for &FpFieldElement<B> {
    type Output = FpFieldElement<B>;

    fn div(self, rhs: Self) -> Self::Output {
        let inverse = rhs.invert().expect("division by zero in Fp");
        self.multiply(&inverse)
    }
}

impl<B: FpInteger> Neg for &FpFieldElement<B> {
    type Output = FpFieldElement<B>;

    fn neg(self) -> Self::Output {
        if self.is_zero() {
            self.clone()
        } else {
            &self.zero() - self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(q: u32, value: u32) -> FpFieldElement {
        FpField::new(BigUint::from(q)).element(&BigUint::from(value))
    }

    #[test]
    fn montgomery_arithmetic_stays_in_range() {
        let x = element(17, 5);
        let y = x.element_from_big_uint(&BigUint::from(9_u8));
        assert_eq!((&x + &y).to_big_uint(), BigUint::from(14_u8));
        assert_eq!((&x - &y).to_big_uint(), BigUint::from(13_u8));
        assert_eq!((&x * &y).to_big_uint(), BigUint::from(11_u8));
        assert_eq!((&x / &y).to_big_uint(), BigUint::from(10_u8));
        assert_eq!(x.square().to_big_uint(), BigUint::from(8_u8));
    }

    #[test]
    fn sqrt_covers_all_odd_prime_branches() {
        for q in [11_u32, 13, 17] {
            let x = element(q, 4);
            let root = x.sqrt().expect("four is a quadratic residue");
            assert_eq!(root.square(), x);
        }
        assert!(element(17, 3).sqrt().is_none());
    }
}
