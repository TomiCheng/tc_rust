//! 曲線參數與具體點型別之間的靜態連結層。
//!
//! Fp 與 F2m 曲線共享係數、階與 cofactor，但各自的體元素與點公式不同；
//! 關聯型別讓演算法保持全泛型，也讓未來像 BC `custom/sec` 的每曲線特化欄位
//! 能提供自己的型別，不需要 trait object。
//!
//! # Draft API
//!
//! 此簽章是 step 1 草案，預期會在 step 3 接受真實 Fp 實作壓力後大改；
//! 請勿視為穩定 API。

use crate::{FieldElement, Point};

/// 橢圓曲線的靜態型別介面。
pub trait Curve: Clone + Eq {
    /// 曲線所屬體域的元素型別。
    type Field: FieldElement;

    /// 曲線點型別。
    type Point: Point<Curve = Self, Field = Self::Field>;

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
}
