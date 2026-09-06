//! 不綁定 Fp、F2m 或特定大整數 crate 的純量乘演算法。
//!
//! 標量的位元存取由 [`Curve`] 提供，因此 `tc_ec_core` 不依賴大整數實作，
//! 同一份 double-and-add 也能套用到動態整數、固定寬度整數與未來特化曲線。

use crate::{Curve, Point};

/// 使用由最高位到最低位的 double-and-add 計算 `scalar * point`。
///
/// 此函式用來驗證 trait 足以承載跨曲線演算法；它是變動時間實作，不應直接
/// 用於秘密純量。
pub fn scalar_mul<C: Curve>(point: &C::Point, scalar: &C::Scalar) -> C::Point {
    let mut result = point.identity();
    let mut bit = C::scalar_bit_length(scalar);
    while bit > 0 {
        bit -= 1;
        result = result.double();
        if C::scalar_test_bit(scalar, bit) {
            result = result.add(point);
        }
    }
    result
}
