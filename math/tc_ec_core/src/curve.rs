//! 曲線參數與具體點型別之間的靜態連結層。
//!
//! Fp 與 F2m 曲線共享係數、階與 cofactor，但各自的體元素與點公式不同；
//! 關聯型別讓演算法保持全泛型，也讓未來像 BC `custom/sec` 的每曲線特化欄位
//! 能提供自己的型別，不需要 trait object。
//!
//! # API 狀態
//!
//! Step 3 以真實 Fp 實作壓測後，移除了演算法不需要的 `Clone + Eq` 限制，
//! 讓未來 BC `custom/sec` 形式的每曲線特化型別不必配合多餘界限。此介面仍在
//! 拆分期，請勿視為穩定 API。

use alloc::sync::Arc;

use crate::{CoordinateSystem, FieldElement, Point};

/// 橢圓曲線的靜態型別介面。
pub trait Curve {
    /// 曲線所屬體域的元素型別。
    type Field: FieldElement;

    /// 曲線點型別。
    type Point: Point<Curve = Self>;

    /// 標量、群階與 cofactor 使用的無號整數型別。
    type Scalar: Clone;

    /// 曲線係數 `a`。
    fn a(&self) -> &Self::Field;

    /// 曲線係數 `b`。
    fn b(&self) -> &Self::Field;

    /// 子群階；未知時為 `None`。
    fn order(&self) -> Option<&Self::Scalar>;

    /// Cofactor；未知時為 `None`。
    fn cofactor(&self) -> Option<&Self::Scalar>;

    /// 建立本曲線的群單位點。
    fn identity(self: &Arc<Self>) -> Self::Point;

    /// 由已屬於本曲線體域的 affine 座標建立點。
    fn create_point(self: &Arc<Self>, x: Self::Field, y: Self::Field) -> Self::Point;

    /// 曲線使用的點座標系。
    fn coordinate_system(&self) -> CoordinateSystem;

    /// 標量的有效位元長度，供不綁定大整數 crate 的共用演算法使用。
    fn scalar_bit_length(scalar: &Self::Scalar) -> usize;

    /// 讀取標量位元，供不綁定大整數 crate 的共用演算法使用。
    fn scalar_test_bit(scalar: &Self::Scalar, index: usize) -> bool;

    /// 標量是否為零。
    fn scalar_is_zero(scalar: &Self::Scalar) -> bool;

    /// 將無號標量右移一位。
    fn scalar_shr1(scalar: &Self::Scalar) -> Self::Scalar;

    /// 將無號標量右移 `count` 位。
    ///
    /// 預設實作只要求既有的一位位移契約；固定寬與動態大整數後端應覆寫成
    /// 自己的 word-level 位移，讓 compact wNAF 能一次跳過連續零位元。
    fn scalar_shr(scalar: &Self::Scalar, count: usize) -> Self::Scalar {
        let mut shifted = scalar.clone();
        for _ in 0..count {
            shifted = Self::scalar_shr1(&shifted);
        }
        shifted
    }

    /// 讀取標量最低 `width` 位，等價於 `scalar mod 2^width`。
    ///
    /// `width` 不得超過 32。
    fn scalar_low_bits(scalar: &Self::Scalar, width: usize) -> u32;

    /// 計算 `scalar - digit`。
    ///
    /// 標量本身是無號整數，但 wNAF digit 可以是負數；例如 digit 為 `-3`
    /// 時，本函式必須回傳 `scalar + 3`。
    fn scalar_sub_digit(scalar: &Self::Scalar, digit: i32) -> Self::Scalar;

    /// 使用預設的變動時間 wNAF 乘法器計算 `scalar * point`。
    ///
    /// 此方法只適合公開標量；秘密標量需要另行實作常數時間乘法器。
    fn multiply(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point
    where
        Self: Sized,
    {
        crate::wnaf_mul_point::<Self>(point, scalar)
    }
}
