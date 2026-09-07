//! secp256r1 的固定欄位元素。

use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::U256;
use tc_ec_core::{FieldElement, PrimeFieldElement};

use crate::secp256r1_field::{SecP256R1Field, gte, is_one, is_zero};

/// 以八個 little-endian 32-bit limbs 保存的 secp256r1 體元素。
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecP256R1FieldElement(pub(crate) [u32; 8]);

impl SecP256R1FieldElement {
    /// 加法單位元。
    pub const ZERO: Self = Self([0; 8]);

    /// 乘法單位元。
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    /// 從 `[0, p)` 的固定寬整數建立體元素。
    pub fn from_uint(value: &U256) -> Option<Self> {
        let mut words = [0_u32; 8];
        value
            .write_le_u32(&mut words)
            .expect("U256 always fits eight u32 words");
        Self::from_words(words)
    }

    /// 從八個 little-endian words 建立體元素。
    pub fn from_words(words: [u32; 8]) -> Option<Self> {
        // Canonical-input validation intentionally exposes acceptance through Option.
        (gte(&words, &SecP256R1Field::P).unwrap_u8() == 0).then_some(Self(words))
    }

    /// 轉回一般固定寬整數。
    pub fn to_uint(&self) -> U256 {
        U256::from_le_u32(&self.0).expect("eight u32 words fit U256")
    }

    /// 寫入固定 32-byte big-endian 表示。
    pub fn encode_to(&self, output: &mut [u8; 32]) {
        self.to_uint()
            .write_be_bytes(output)
            .expect("U256 encoding buffer has exact width");
    }

    /// 回傳底層 little-endian words。
    pub const fn as_words(&self) -> &[u32; 8] {
        &self.0
    }

    /// 是否為零。
    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }

    /// 是否為一。
    pub fn is_one(&self) -> bool {
        is_one(&self.0)
    }

    /// 最低位元是否為一。
    pub const fn test_bit_zero(&self) -> bool {
        self.0[0] & 1 != 0
    }

    /// 體域加法。
    pub fn add(&self, rhs: &Self) -> Self {
        Self(SecP256R1Field::add(&self.0, &rhs.0))
    }

    /// 體域減法。
    pub fn subtract(&self, rhs: &Self) -> Self {
        Self(SecP256R1Field::subtract(&self.0, &rhs.0))
    }

    /// 體域乘法。
    pub fn multiply(&self, rhs: &Self) -> Self {
        Self(SecP256R1Field::multiply(&self.0, &rhs.0))
    }

    /// 體域平方。
    pub fn square(&self) -> Self {
        Self(SecP256R1Field::square(&self.0))
    }

    /// 加法反元素。
    pub fn negate(&self) -> Self {
        Self(SecP256R1Field::negate(&self.0))
    }

    /// 乘法反元素；零回傳 `None`。
    pub fn invert(&self) -> Option<Self> {
        SecP256R1Field::invert(&self.0).map(Self)
    }

    /// 依 bc 的固定 addition chain 計算並驗證平方根。
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(*self);
        }

        let x1 = self.0;
        let mut t1 = SecP256R1Field::square(&x1);
        t1 = SecP256R1Field::multiply(&t1, &x1);
        let mut t2 = SecP256R1Field::square_n(&t1, 2);
        t2 = SecP256R1Field::multiply(&t2, &t1);
        t1 = SecP256R1Field::square_n(&t2, 4);
        t1 = SecP256R1Field::multiply(&t1, &t2);
        t2 = SecP256R1Field::square_n(&t1, 8);
        t2 = SecP256R1Field::multiply(&t2, &t1);
        t1 = SecP256R1Field::square_n(&t2, 16);
        t1 = SecP256R1Field::multiply(&t1, &t2);
        t1 = SecP256R1Field::square_n(&t1, 32);
        t1 = SecP256R1Field::multiply(&t1, &x1);
        t1 = SecP256R1Field::square_n(&t1, 96);
        t1 = SecP256R1Field::multiply(&t1, &x1);
        t1 = SecP256R1Field::square_n(&t1, 94);
        t2 = SecP256R1Field::square(&t1);
        (t2 == x1).then_some(Self(t1))
    }
}

impl FieldElement for SecP256R1FieldElement {
    fn is_zero(&self) -> bool {
        self.is_zero()
    }

    fn is_one(&self) -> bool {
        self.is_one()
    }

    fn add(&self, rhs: &Self) -> Self {
        self.add(rhs)
    }

    fn sub(&self, rhs: &Self) -> Self {
        self.subtract(rhs)
    }

    fn mul(&self, rhs: &Self) -> Self {
        self.multiply(rhs)
    }

    fn square(&self) -> Self {
        self.square()
    }

    fn sqrt(&self) -> Option<Self> {
        self.sqrt()
    }

    fn negate(&self) -> Self {
        self.negate()
    }

    fn invert(&self) -> Option<Self> {
        self.invert()
    }
}

impl PrimeFieldElement for SecP256R1FieldElement {
    type BigUint = U256;

    fn element_from_big_uint(&self, value: &Self::BigUint) -> Self {
        Self::from_uint(value).expect("field element must be smaller than secp256r1 modulus")
    }

    fn to_big_uint(&self) -> Self::BigUint {
        self.to_uint()
    }
}

impl Add for &SecP256R1FieldElement {
    type Output = SecP256R1FieldElement;

    fn add(self, rhs: Self) -> Self::Output {
        SecP256R1FieldElement::add(self, rhs)
    }
}

impl Sub for &SecP256R1FieldElement {
    type Output = SecP256R1FieldElement;

    fn sub(self, rhs: Self) -> Self::Output {
        SecP256R1FieldElement::subtract(self, rhs)
    }
}

impl Mul for &SecP256R1FieldElement {
    type Output = SecP256R1FieldElement;

    fn mul(self, rhs: Self) -> Self::Output {
        SecP256R1FieldElement::multiply(self, rhs)
    }
}

impl Neg for &SecP256R1FieldElement {
    type Output = SecP256R1FieldElement;

    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl core::fmt::Debug for SecP256R1FieldElement {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_tuple("SecP256R1FieldElement")
            .field(&self.to_uint())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_and_square_root_satisfy_field_identities() {
        let value = SecP256R1FieldElement::from_words([
            0x89ab_cdef,
            0x0123_4567,
            0x7654_3211,
            0xfedc_ba98,
            0x55aa_00ff,
            0x1020_3040,
            0x3141_5926,
            0x2718_2818,
        ])
        .unwrap();
        assert_eq!(
            &value * &value.invert().unwrap(),
            SecP256R1FieldElement::ONE
        );

        let square = value.square();
        let root = square.sqrt().unwrap();
        assert_eq!(root.square(), square);
        assert!(
            SecP256R1FieldElement::from_uint(&U256::from_le_u32(&SecP256R1Field::P).unwrap())
                .is_none()
        );
    }
}
