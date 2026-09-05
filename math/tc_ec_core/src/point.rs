//! 曲線點群運算的共通層。
//!
//! Fp 與 F2m 的座標公式不同，但單位點、加法、倍點、反元素與正規化的群語意
//! 相同。關聯型別將點鎖回具體曲線與體元素，讓泛型演算法可靜態分派，並保留
//! per-curve 特化實作空間。
//!
//! # Draft API
//!
//! 此簽章是 step 1 草案，預期會在 step 3 接受真實 Fp 實作壓力後大改；
//! 請勿視為穩定 API。

use crate::{Curve, FieldElement};

/// 橢圓曲線點的群運算介面。
pub trait Point: Clone + Eq {
    /// 點所屬的曲線型別。
    type Curve: Curve<Field = Self::Field, Point = Self>;

    /// 座標的體元素型別。
    type Field: FieldElement;

    /// 產生同一條曲線上的群單位點。
    fn identity(&self) -> Self;

    /// 是否為群單位點。
    fn is_identity(&self) -> bool;

    /// 點加法。
    fn add(&self, rhs: &Self) -> Self;

    /// 點倍乘二。
    fn double(&self) -> Self;

    /// 點的加法反元素。
    fn negate(&self) -> Self;

    /// 轉為正規化表示。
    fn normalize(&self) -> Self;
}
