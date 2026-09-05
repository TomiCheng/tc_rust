//! 質數體元素的專屬層。
//!
//! F2m 實作證實平方根並非 Fp 專屬，因此 `sqrt` 已上移到共同
//! [`FieldElement`]。本層只保留 Fp 與無號整數表示之間的互轉；`BigUint`
//! 以關聯型別表達，使零相依的 core 不必直接依賴某個大整數 crate。
//!
//! # API 狀態
//!
//! Step 3 已用 Montgomery Fp 元素驗證從相同體域實例轉入、轉出 `BigUint`
//! 的簽章；介面仍在拆分期，請勿視為穩定 API。

use crate::FieldElement;

/// 質數體 Fp 元素的專屬介面。
pub trait PrimeFieldElement: FieldElement {
    /// 實作者使用的無號大整數；step 3 的 Fp 實作會綁定為 `BigUint`。
    type BigUint;

    /// 在同一體域中由 `[0, q)` 的無號整數建立元素。
    fn element_from_big_uint(&self, value: &Self::BigUint) -> Self;

    /// 離開體域表示並回傳 `[0, q)` 的無號整數。
    fn to_big_uint(&self) -> Self::BigUint;
}
