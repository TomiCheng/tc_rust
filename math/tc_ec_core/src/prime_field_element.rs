//! 質數體元素的專屬層。
//!
//! Fp 的平方根與 F2m 的 `solve_quadratic` 在曲線點解壓縮中扮演相同角色，
//! 但數學與實作完全不同，因此平方根只放在本 trait。`BigUint` 以關聯型別
//! 表達，使零相依的 core 不必直接依賴某個大整數 crate。
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

    /// 若存在，回傳本元素的一個平方根。
    fn sqrt(&self) -> Option<Self>;

    /// 在同一體域中由 `[0, q)` 的無號整數建立元素。
    fn element_from_big_uint(&self, value: &Self::BigUint) -> Self;

    /// 離開體域表示並回傳 `[0, q)` 的無號整數。
    fn to_big_uint(&self) -> Self::BigUint;
}
