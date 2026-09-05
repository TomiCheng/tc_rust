//! 曲線點群運算的共通層。
//!
//! Fp 與 F2m 的座標公式不同，但單位點、加法、倍點、反元素與正規化的群語意
//! 相同。關聯型別將點鎖回具體曲線與體元素，讓泛型演算法可靜態分派，並保留
//! per-curve 特化實作空間。
//!
//! # API 狀態
//!
//! Step 3 的 Fp 實作證實 `Field` 可由 `Self::Curve::Field` 唯一決定，因此移除
//! 點上的重複關聯型別。這可避免泛型演算法與 per-curve 特化實作維護兩份相同
//! 約束；介面仍在拆分期，請勿視為穩定 API。

use crate::Curve;

/// 橢圓曲線點的群運算介面。
pub trait Point: Clone + Eq {
    /// 點所屬的曲線型別。
    type Curve: Curve<Point = Self>;

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
