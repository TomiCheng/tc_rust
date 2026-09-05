//! 動態與固定寬度二元多項式的共通操作層。
//!
//! 演算法只依賴此 trait 與 [`BinPolyMultiplier`]，即可在配置型
//! `BinaryPoly` 和無配置 [`crate::FixedBinaryPoly`] 之間靜態分派。
//! `from_limbs` 的輸入表示刻意留在各具體型別，避免把配置策略塞進共通介面。

use core::ops::Add;

#[cfg(feature = "alloc")]
use crate::BinaryPoly;
use crate::{BinPolyError, BinPolyMultiplier, FixedBinaryPoly};

/// 綁定約簡多項式的二元多項式值操作。
pub trait BinaryPolyOps: Sized + Clone + Eq + for<'a> Add<&'a Self, Output = Self> {
    /// 建立指定 quotient ring 或 field 的零。
    fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError>;

    /// 建立指定 quotient ring 或 field 的一。
    fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError>;

    /// 回傳此值使用的乘法與約簡設定。
    fn multiplier(&self) -> &BinPolyMultiplier;

    /// 回傳限位小端 limbs。
    fn as_limbs(&self) -> &[u64];

    /// 計算同一 modulus 下的乘積。
    fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError>;

    /// 計算平方。
    fn square(&self) -> Self;

    /// 計算連續 `count` 次平方。
    fn square_pow(&self, count: usize) -> Self;

    /// 計算乘法反元素。
    fn invert(&self) -> Result<Self, BinPolyError>;
}

#[cfg(feature = "alloc")]
impl BinaryPolyOps for BinaryPoly {
    fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        Ok(BinaryPoly::zero(multiplier))
    }

    fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        Ok(BinaryPoly::one(multiplier))
    }

    fn multiplier(&self) -> &BinPolyMultiplier {
        BinaryPoly::multiplier(self)
    }

    fn as_limbs(&self) -> &[u64] {
        BinaryPoly::as_limbs(self)
    }

    fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
        BinaryPoly::multiply(self, rhs)
    }

    fn square(&self) -> Self {
        BinaryPoly::square(self)
    }

    fn square_pow(&self, count: usize) -> Self {
        BinaryPoly::square_pow(self, count)
    }

    fn invert(&self) -> Result<Self, BinPolyError> {
        BinaryPoly::invert(self)
    }
}

impl<const N: usize> BinaryPolyOps for FixedBinaryPoly<N> {
    fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        FixedBinaryPoly::zero(multiplier)
    }

    fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
        FixedBinaryPoly::one(multiplier)
    }

    fn multiplier(&self) -> &BinPolyMultiplier {
        FixedBinaryPoly::multiplier(self)
    }

    fn as_limbs(&self) -> &[u64] {
        FixedBinaryPoly::as_limbs(self)
    }

    fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
        FixedBinaryPoly::multiply(self, rhs)
    }

    fn square(&self) -> Self {
        FixedBinaryPoly::square(self)
    }

    fn square_pow(&self, count: usize) -> Self {
        FixedBinaryPoly::square_pow(self, count)
    }

    fn invert(&self) -> Result<Self, BinPolyError> {
        FixedBinaryPoly::invert(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "alloc")]
    use alloc::vec;

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_trait_forwards_and_satisfies_field_properties() {
        let multiplier = BinPolyMultiplier::trinomial(113, 9).unwrap();
        let value = BinaryPoly::from_limbs(multiplier.clone(), vec![0x0123_4567_89AB_CDEF, 0x1234])
            .unwrap();

        assert_eq!(
            <BinaryPoly as BinaryPolyOps>::zero(multiplier.clone()).unwrap(),
            BinaryPoly::zero(multiplier.clone())
        );
        let one = <BinaryPoly as BinaryPolyOps>::one(multiplier.clone()).unwrap();
        assert_eq!(one, BinaryPoly::one(multiplier));
        assert_eq!(BinaryPolyOps::multiplier(&value), value.multiplier());
        assert_eq!(BinaryPolyOps::as_limbs(&value), value.as_limbs());
        assert_eq!(BinaryPolyOps::square(&value), value.square());
        assert_eq!(BinaryPolyOps::square_pow(&value, 7), value.square_pow(7));
        assert_eq!(BinaryPolyOps::invert(&value), value.invert());

        let square = value.multiply(&value).unwrap();
        assert_eq!(value.square(), square);
        let inverse = value.invert().unwrap();
        assert_eq!(value.multiply(&inverse).unwrap(), one);
        assert_eq!(
            BinaryPolyOps::multiply(&value, &inverse).unwrap(),
            value.multiply(&inverse).unwrap()
        );
    }

    #[test]
    fn fixed_trait_forwards_and_satisfies_field_properties() {
        type Poly = FixedBinaryPoly<3>;

        let multiplier = BinPolyMultiplier::pentanomial(163, 3, 6, 7).unwrap();
        let value = Poly::from_limbs(
            multiplier.clone(),
            [0x0123_4567_89AB_CDEF, 0x0FED_CBA9_8765_4321, 0x1234],
        )
        .unwrap();

        assert_eq!(
            <Poly as BinaryPolyOps>::zero(multiplier.clone()).unwrap(),
            Poly::zero(multiplier.clone()).unwrap()
        );
        let one = <Poly as BinaryPolyOps>::one(multiplier.clone()).unwrap();
        assert_eq!(one, Poly::one(multiplier).unwrap());
        assert_eq!(BinaryPolyOps::multiplier(&value), value.multiplier());
        assert_eq!(BinaryPolyOps::as_limbs(&value), value.as_limbs());
        assert_eq!(BinaryPolyOps::square(&value), value.square());
        assert_eq!(BinaryPolyOps::square_pow(&value, 7), value.square_pow(7));
        assert_eq!(BinaryPolyOps::invert(&value), value.invert());

        let square = value.multiply(&value).unwrap();
        assert_eq!(value.square(), square);
        let inverse = value.invert().unwrap();
        assert_eq!(value.multiply(&inverse).unwrap(), one);
        assert_eq!(
            BinaryPolyOps::multiply(&value, &inverse).unwrap(),
            value.multiply(&inverse).unwrap()
        );
    }
}
