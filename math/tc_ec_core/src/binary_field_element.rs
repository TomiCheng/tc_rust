//! 二元擴張體元素的專屬層。
//!
//! F2m 的 trace 與 half-trace 不適用於 Fp。`solve_quadratic` 需要曲線的
//! 係數與解壓縮規則，BC 與舊 `tc_ec` 也都把它放在曲線層，因此不再放在
//! 體元素 trait。平方根則因 Fp/F2m 都有而移到共同 [`FieldElement`]。
//!
//! # API 狀態
//!
//! F2m 實作已把 trace 定為誠實表達 `{0, 1}` 的 `u8`；介面仍在拆分期，
//! 請勿視為穩定 API。

use crate::FieldElement;

/// 二元擴張體 F2m 元素的專屬介面。
pub trait BinaryFieldElement: FieldElement {
    /// 回傳絕對 trace（0 或 1）。
    fn trace(&self) -> u8;

    /// 計算 half-trace。
    fn half_trace(&self) -> Self;
}
