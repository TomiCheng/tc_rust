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
    type Scalar;

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
}
