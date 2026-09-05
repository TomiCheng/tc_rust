//! F2m 元素與二進位多項式表示之間的轉碼層。
//!
//! [`tc_binpoly::BinaryPolyOps`] 已涵蓋所有體域算術；唯獨建值時，配置版接受
//! `Vec<u64>`、固定版接受 `[u64; N]`，無法用同一個參數型別表達。本 trait
//! 只補這個表示邊界，不加入任何新演算法。

use tc_binpoly::{BinPolyError, BinPolyMultiplier, BinaryPoly, BinaryPolyOps, FixedBinaryPoly};

/// 可由 little-endian limb slice 建立的二進位多項式值。
pub trait F2mPolynomial: BinaryPolyOps {
    /// 由已約簡且長度符合 multiplier 的 limbs 建值。
    fn from_limb_slice(multiplier: BinPolyMultiplier, limbs: &[u64]) -> Result<Self, BinPolyError>;
}

impl F2mPolynomial for BinaryPoly {
    fn from_limb_slice(multiplier: BinPolyMultiplier, limbs: &[u64]) -> Result<Self, BinPolyError> {
        BinaryPoly::from_limbs(multiplier, limbs.to_vec())
    }
}

impl<const N: usize> F2mPolynomial for FixedBinaryPoly<N> {
    fn from_limb_slice(multiplier: BinPolyMultiplier, limbs: &[u64]) -> Result<Self, BinPolyError> {
        let limbs: [u64; N] = limbs.try_into().map_err(|_| BinPolyError::InvalidLength {
            expected: N,
            actual: limbs.len(),
        })?;
        FixedBinaryPoly::from_limbs(multiplier, limbs)
    }
}
