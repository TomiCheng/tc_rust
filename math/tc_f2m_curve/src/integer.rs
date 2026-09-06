//! F2m 曲線係數、座標與純量使用的整數邊界。
//!
//! 二元體算術完全由 `tc_binpoly` 負責；整數只在曲線參數、SEC 座標轉碼與
//! 純量位元掃描出現。wNAF 另需要右移與小 digit 加減，但仍刻意不要求
//! Montgomery 或模反元素能力，讓 [`tc_bigint::BigUint`] 與固定寬度整數
//! 共用同一套曲線實作。

use core::ops::{Add, Shr, Sub};

use tc_bigint::{ArrayEncoding, BitOps, FromPrimitive};

/// F2m 曲線所需的最小無號整數能力集合。
pub trait F2mInteger:
    BitOps<Output = Self>
    + ArrayEncoding
    + Clone
    + Ord
    + FromPrimitive
    + Shr<usize, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
{
}

impl<T> F2mInteger for T where
    T: BitOps<Output = T>
        + ArrayEncoding
        + Clone
        + Ord
        + FromPrimitive
        + Shr<usize, Output = T>
        + for<'a> Add<&'a T, Output = T>
        + for<'a> Sub<&'a T, Output = T>
{
}
