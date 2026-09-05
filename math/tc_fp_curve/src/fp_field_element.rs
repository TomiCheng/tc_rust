//! 以 Montgomery domain 表示的質數體元素。
//!
//! 舊 `tc_ec` 把帶符號 `BigInt` 與快速 reduction residue 放在每個元素中；
//! 本實作改用 `BigUint`，以共享的 [`FpField`] 保存質數與 Montgomery 參數，
//! 元素永遠代表 `[0, q)`，因此不再需要任何符號修正分支。

use alloc::sync::Arc;
use core::ops::{Add, Div, Mul, Neg, Sub};

use tc_bigint::modular::{MontyForm, MontyParams};
use tc_bigint::{BigUint, Odd};

/// 同一個 Fp 體域共用的 Montgomery 參數。
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FpField {
    params: MontyParams<BigUint>,
}

impl FpField {
    pub(crate) fn new(q: BigUint) -> Arc<Self> {
        let modulus = Odd::new(q).expect("curve prime is odd");
        Arc::new(Self {
            params: MontyParams::new(modulus),
        })
    }

    pub(crate) fn q(&self) -> &BigUint {
        self.params.modulus()
    }

    pub(crate) fn element(self: &Arc<Self>, value: &BigUint) -> FpFieldElement {
        assert!(value < self.q(), "value invalid for Fp field element");
        FpFieldElement {
            field: Arc::clone(self),
            value: MontyForm::new(value, self.params.clone()),
        }
    }
}

/// 質數體 `GF(q)` 的一個元素。
#[derive(Clone)]
pub struct FpFieldElement {
    field: Arc<FpField>,
    value: MontyForm<BigUint>,
}

impl FpFieldElement {
    fn with_monty(&self, value: MontyForm<BigUint>) -> Self {
        Self {
            field: Arc::clone(&self.field),
            value,
        }
    }

    fn multiply(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.field, rhs.field, "different Fp fields");
        self.with_monty(&self.value * &rhs.value)
    }

    /// 回傳體域質數 `q`。
    pub fn q(&self) -> &BigUint {
        self.field.q()
    }

    /// 回傳 `q` 的有效位元數。
    pub fn field_size(&self) -> usize {
        self.q().bits()
    }

    /// 離開 Montgomery domain，回傳 `[0, q)` 的標準整數。
    pub fn to_big_uint(&self) -> BigUint {
        self.value.retrieve()
    }

    /// 在同一個 Fp 體域中建立元素。
    pub fn element_from_big_uint(&self, value: &BigUint) -> Self {
        self.field.element(value)
    }

    /// 同一體域的加法單位元。
    pub fn zero(&self) -> Self {
        self.element_from_big_uint(&BigUint::default())
    }

    /// 同一體域的乘法單位元。
    pub fn one(&self) -> Self {
        self.element_from_big_uint(&BigUint::from(1_u8))
    }

    /// 是否為零。
    pub fn is_zero(&self) -> bool {
        self.to_big_uint().is_zero()
    }

    /// 是否為一。
    pub fn is_one(&self) -> bool {
        self.to_big_uint() == BigUint::from(1_u8)
    }

    /// 在 Montgomery domain 內平方。
    pub fn square(&self) -> Self {
        self.with_monty(self.value.square())
    }

    /// 在 Montgomery domain 內做公開指數次方。
    pub fn pow(&self, exponent: &BigUint) -> Self {
        self.with_monty(self.value.pow(exponent))
    }

    /// 回傳乘法反元素；零沒有反元素。
    ///
    /// 使用費馬小定理 `x^(q-2)`，讓值全程留在 Montgomery domain，省去
    /// `retrieve → ModInverse → MontyForm::new` 的兩次轉換。取捨是一般
    /// `pow` 比專用 safegcd 反元素昂貴；日後可在不改公開表示的前提下替換。
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let exponent = self.q() - 2_u8;
        Some(self.pow(&exponent))
    }

    /// 回傳平方根；非二次剩餘時為 `None`。
    ///
    /// `q ≡ 3 (mod 4)` 與 `q ≡ 5 (mod 8)` 使用 BC 的直接公式；
    /// `q ≡ 1 (mod 8)` 使用 Lucas sequence。所有 modular power 都透過
    /// [`MontyForm::pow`]，不離開 Montgomery domain。
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(self.clone());
        }

        let q = self.q();
        assert!(q.test_bit(0), "sqrt does not support an even modulus");
        let one_value = BigUint::from(1_u8);

        if q.test_bit(1) {
            let exponent = (q >> 2) + &one_value;
            return self.check_sqrt(self.pow(&exponent));
        }

        if q.test_bit(2) {
            let t1 = self.pow(&(q >> 3));
            let t2 = &t1 * self;
            let t3 = &t2 * &t1;
            if t3.is_one() {
                return self.check_sqrt(t2);
            }
            let two = self.element_from_big_uint(&BigUint::from(2_u8));
            let t4 = two.pow(&(q >> 2));
            return self.check_sqrt(&t2 * &t4);
        }

        let legendre_exponent = q >> 1;
        if !self.pow(&legendre_exponent).is_one() {
            return None;
        }

        let two_x = self + self;
        let four_x = &two_x + &two_x;
        let k = &legendre_exponent + &one_value;
        let q_minus_one_value = q - &one_value;
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
            p_value = &p_value + &one_value;
        }
    }

    fn check_sqrt(&self, candidate: Self) -> Option<Self> {
        (candidate.square() == *self).then_some(candidate)
    }

    fn mod_half_abs(&self, value: &Self) -> Self {
        let value = value.to_big_uint();
        let half = if value.test_bit(0) {
            (self.q() - &value) >> 1
        } else {
            value >> 1
        };
        self.element_from_big_uint(&half)
    }

    fn lucas_sequence(&self, p: &Self, lucas_q: &Self, k: &BigUint) -> (Self, Self) {
        let n = k.bits();
        let s = k
            .lowest_set_bit()
            .expect("lucas_sequence requires non-zero k");

        let mut uh = self.one();
        let mut vl = self.element_from_big_uint(&BigUint::from(2_u8));
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

impl PartialEq for FpFieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.field == other.field && self.value == other.value
    }
}

impl Eq for FpFieldElement {}

impl core::fmt::Debug for FpFieldElement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpFieldElement")
            .field("value", &self.to_big_uint())
            .field("q", self.q())
            .finish()
    }
}

impl Add for &FpFieldElement {
    type Output = FpFieldElement;

    fn add(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.field, rhs.field, "different Fp fields");
        self.with_monty(&self.value + &rhs.value)
    }
}

impl Sub for &FpFieldElement {
    type Output = FpFieldElement;

    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.field, rhs.field, "different Fp fields");
        self.with_monty(&self.value - &rhs.value)
    }
}

impl Mul for &FpFieldElement {
    type Output = FpFieldElement;

    fn mul(self, rhs: Self) -> Self::Output {
        self.multiply(rhs)
    }
}

impl Div for &FpFieldElement {
    type Output = FpFieldElement;

    fn div(self, rhs: Self) -> Self::Output {
        let inverse = rhs.invert().expect("division by zero in Fp");
        self.multiply(&inverse)
    }
}

impl Neg for &FpFieldElement {
    type Output = FpFieldElement;

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
