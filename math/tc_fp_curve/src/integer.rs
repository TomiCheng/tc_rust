//! Fp 曲線演算法共用的整數能力集合。
//!
//! 動態 [`tc_bigint::BigUint`] 與固定寬度 [`tc_bigint::FixedBigUint`] 都透過
//! blanket implementation 滿足此介面。Montgomery 形式由 [`MontyInteger`]
//! 反向連結，因此曲線程式碼不需要知道實際 residue 型別。

use core::fmt::Debug;
use core::ops::Shr;

use tc_bigint::{
    ArrayEncoding, BitOps, FromPrimitive, ModInverse, NumRef, RandomMod, modular::MontyInteger,
};

/// 泛型 Fp 曲線所需的無號整數能力集合。
pub trait FpInteger:
    MontyInteger
    + NumRef
    + Clone
    + Ord
    + Debug
    + BitOps<Output = Self>
    + ModInverse<Output = Self>
    + FromPrimitive
    + ArrayEncoding
    + RandomMod
    + Shr<usize, Output = Self>
{
}

impl<T> FpInteger for T where
    T: MontyInteger
        + NumRef
        + Clone
        + Ord
        + Debug
        + BitOps<Output = T>
        + ModInverse<Output = T>
        + FromPrimitive
        + ArrayEncoding
        + RandomMod
        + Shr<usize, Output = T>
{
}
