//! 二元擴張體元素的專屬層。
//!
//! F2m 的 trace、half-trace 與解二次方程不適用於 Fp；其中
//! `solve_quadratic` 與 Fp 的 `sqrt` 同樣服務點解壓縮，卻需要不同演算法，
//! 因此兩者分層而不塞進共同 `FieldElement`。
//!
//! # API 狀態
//!
//! Step 3 尚未實作 F2m；此介面保留為下一階段草案，請勿視為穩定 API。

use crate::FieldElement;

/// 二元擴張體 F2m 元素的專屬介面。
pub trait BinaryFieldElement: FieldElement {
    /// 回傳絕對 trace（0 或 1）。
    fn trace(&self) -> u8;

    /// 計算 half-trace。
    fn half_trace(&self) -> Self;

    /// 解 `z² + z = self`；無解時回傳 `None`。
    fn solve_quadratic(&self) -> Option<Self>;
}
