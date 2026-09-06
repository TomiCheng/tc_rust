//! F2m 曲線係數、座標與純量使用的整數邊界。
//!
//! 二元體算術完全由 `tc_binpoly` 負責；整數只在曲線參數、SEC 座標轉碼與
//! 純量位元掃描出現。因此這裡刻意不要求 Montgomery 或模反元素能力，讓
//! [`tc_bigint::BigUint`] 與固定寬度整數共用同一套曲線實作。

use tc_bigint::{ArrayEncoding, BitOps};

/// F2m 曲線所需的最小無號整數能力集合。
pub trait F2mInteger: BitOps + ArrayEncoding + Clone + Ord {}

impl<T> F2mInteger for T where T: BitOps + ArrayEncoding + Clone + Ord {}
