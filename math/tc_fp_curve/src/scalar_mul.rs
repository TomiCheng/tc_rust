//! 以 core traits 撰寫的跨曲線純量乘範例。
//!
//! 此演算法只依賴 [`Curve`] 與其關聯的 [`Point`]，因此同一份程式可套用到
//! 通用 `FpCurve`，也可套用到未來擁有專用欄位與點型別的 `custom/sec` 曲線。

use tc_bigint::BigUint;
use tc_ec_core::{Curve, Point};

/// 使用由最高位到最低位的 double-and-add 計算 `scalar * point`。
///
/// 此函式的目的在驗證抽象可承載真實泛型演算法；目前未宣稱常數時間，秘密純量
/// 應改用後續的固定視窗或 ladder 實作。
pub fn scalar_mul<C>(point: &C::Point, scalar: &BigUint) -> C::Point
where
    C: Curve<Scalar = BigUint>,
{
    let mut result = point.identity();
    let mut bit = scalar.bits();
    while bit > 0 {
        bit -= 1;
        result = result.double();
        if scalar.test_bit(bit) {
            result = result.add(point);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FpCurve;
    use crate::named_curves::{secp256k1, secp256r1};

    #[test]
    fn generic_algorithm_runs_on_both_named_curves() {
        for (_, point) in [secp256k1(), secp256r1()] {
            for scalar in [0_u32, 1, 2, 19, 255] {
                let scalar = BigUint::from(scalar);
                assert_eq!(
                    scalar_mul::<FpCurve>(&point, &scalar),
                    point.mul_double_and_add(&scalar)
                );
            }
        }
    }
}
