//! 質數體元素的專屬層。
//!
//! Fp 的平方根與 F2m 的 `solve_quadratic` 在曲線點解壓縮中扮演相同角色，
//! 但數學與實作完全不同，因此平方根只放在本 trait。`BigUint` 以關聯型別
//! 表達，使零相依的 core 不必直接依賴某個大整數 crate。
//!
//! # Draft API
//!
//! 此簽章是 step 1 草案，預期會在 step 3 接受真實 Fp 實作壓力後大改；
//! 請勿視為穩定 API。

use crate::FieldElement;

/// 質數體 Fp 元素的專屬介面。
pub trait PrimeFieldElement: FieldElement {
    /// 實作者使用的無號大整數；step 3 的 Fp 實作會綁定為 `BigUint`。
    type BigUint;

    /// 若存在，回傳本元素的一個平方根。
    fn sqrt(&self) -> Option<Self>;

    /// 在同一體域中由 `[0, q)` 的無號整數建立元素。
    fn from_big_uint(&self, value: &Self::BigUint) -> Self;

    /// 離開體域表示並回傳 `[0, q)` 的無號整數。
    fn to_big_uint(&self) -> Self::BigUint;
}
