//! 固定寬度整數底層 limb 運算。
//!
//! 這一層提供每曲線特化等低階實作所需的精選 primitive，而不是公開整個
//! `arithmetic` 內部模組。所有陣列皆採 little-endian [`Limb`](crate::Limb)，
//! 因此 limb 寬度會跟隨目標平台。

pub use crate::arithmetic::{
    fixed_add, fixed_cmp, fixed_is_one, fixed_is_zero, fixed_mul_add_to, fixed_mul_wide,
    fixed_shl_one, fixed_shr_one, fixed_square_wide, fixed_sub,
};
