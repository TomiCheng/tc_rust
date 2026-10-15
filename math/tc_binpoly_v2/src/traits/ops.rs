//! 動態與固定寬度二元多項式的共通操作層。
//!
//! 演算法只依賴此 trait 與 [`BinPolyMultiplier`]，即可在配置型
//! `BinaryPoly` 和無配置 [`crate::FixedBinaryPoly`] 之間靜態分派。
//! `from_limbs` 的輸入表示刻意留在各具體型別，避免把配置策略塞進共通介面。

use core::ops::Add;
use crate::BinPolyError;
//use crate::BinaryPoly;
//use crate::{BinPolyError, BinPolyMultiplier, FixedBinaryPoly};

/// 綁定約簡多項式的二元多項式值操作。
pub trait BinaryPolyOps: Sized + Clone + Eq + for<'a> Add<&'a Self, Output = Self> {
    // /// 建立指定 quotient ring 或 field 的零。
    // fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError>;
    //
    // /// 建立指定 quotient ring 或 field 的一。
    // fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError>;
    //
    // /// 回傳此值使用的乘法與約簡設定。
    // fn multiplier(&self) -> &BinPolyMultiplier;

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

// impl BinaryPolyOps for BinaryPoly {
//     fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
//         Ok(BinaryPoly::zero(multiplier))
//     }
//
//     fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
//         Ok(BinaryPoly::one(multiplier))
//     }
//
//     fn multiplier(&self) -> &BinPolyMultiplier {
//         BinaryPoly::multiplier(self)
//     }
//
//     fn as_limbs(&self) -> &[u64] {
//         BinaryPoly::as_limbs(self)
//     }
//
//     fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
//         BinaryPoly::multiply(self, rhs)
//     }
//
//     fn square(&self) -> Self {
//         BinaryPoly::square(self)
//     }
//
//     fn square_pow(&self, count: usize) -> Self {
//         BinaryPoly::square_pow(self, count)
//     }
//
//     fn invert(&self) -> Result<Self, BinPolyError> {
//         BinaryPoly::invert(self)
//     }
// }

// impl<const N: usize> BinaryPolyOps for FixedBinaryPoly<N> {
//     fn zero(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
//         FixedBinaryPoly::zero(multiplier)
//     }
//
//     fn one(multiplier: BinPolyMultiplier) -> Result<Self, BinPolyError> {
//         FixedBinaryPoly::one(multiplier)
//     }
//
//     fn multiplier(&self) -> &BinPolyMultiplier {
//         FixedBinaryPoly::multiplier(self)
//     }
//
//     fn as_limbs(&self) -> &[u64] {
//         FixedBinaryPoly::as_limbs(self)
//     }
//
//     fn multiply(&self, rhs: &Self) -> Result<Self, BinPolyError> {
//         FixedBinaryPoly::multiply(self, rhs)
//     }
//
//     fn square(&self) -> Self {
//         FixedBinaryPoly::square(self)
//     }
//
//     fn square_pow(&self, count: usize) -> Self {
//         FixedBinaryPoly::square_pow(self, count)
//     }
//
//     fn invert(&self) -> Result<Self, BinPolyError> {
//         FixedBinaryPoly::invert(self)
//     }
// }
