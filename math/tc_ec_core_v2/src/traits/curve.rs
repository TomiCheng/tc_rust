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

use crate::CoordinateSystem;
use super::FieldElement;
use super::Point;
use super::Scalar;

/// 橢圓曲線的靜態型別介面；實作在曲線的 handle 上，例如 `&Curve` 或 `Arc<Curve>`。
pub trait Curve: Clone {
    /// 曲線所屬體域的元素型別。
    type Field: FieldElement;

    /// 曲線點型別。
    type Point: Point<Curve = Self>;

    /// 標量、群階與 cofactor 使用的無號整數型別。
    type Scalar: Scalar;

    /// 曲線係數 `a`。
    fn a(&self) -> &Self::Field;

    /// 曲線係數 `b`。
    fn b(&self) -> &Self::Field;

    /// 子群階；未知時為 `None`。
    fn order(&self) -> Option<&Self::Scalar>;

    /// Cofactor；未知時為 `None`。
    fn cofactor(&self) -> Option<&Self::Scalar>;

    /// 建立本曲線體域的加法單位元。
    ///
    /// 工廠放在曲線而不是 [`FieldElement`] 上，因為執行期曲線需要使用曲線
    /// 持有的模數或約簡參數；編譯期特化曲線則可直接回傳固定常數。
    fn zero(&self) -> Self::Field;

    /// 建立本曲線體域的乘法單位元。
    fn one(&self) -> Self::Field;

    /// 建立本曲線的群單位點。
    fn infinity(&self) -> Self::Point;

    /// 由已屬於本曲線體域的 affine 座標建立點。
    fn create_point(&self, x: Self::Field, y: Self::Field) -> Self::Point;

    /// 曲線使用的點座標系。
    fn coordinate_system(&self) -> CoordinateSystem;

    /// 計算 `scalar * point`。沒有預設實作，乘法器由每條曲線自己選。
    fn multiply(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point
    where
        Self: Sized;
}
