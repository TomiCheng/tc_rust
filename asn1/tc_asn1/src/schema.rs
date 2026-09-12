//! 具名結構的編解碼樣板。
//!
//! 解碼以 [`Fields::new`] 進入 constructed 內容，再按 schema 讀取欄位。
//! 每個成功的解碼路徑最後都必須呼叫 [`Fields::finish`]，避免接受未預期的尾端欄位。
//! CHOICE 自己實作 [`crate::TryDecode`]，OPTIONAL CHOICE 可用 [`Fields::peek`]
//! 判斷；本模組不猜測哪個 tag 屬於某個 CHOICE。
//!
//! 編碼實作 [`SequenceFields`]，再呼叫 [`crate::impl_sequence_encode!`]。
//! sink 只在呼叫期間借用欄位，因此也可接收臨時的 [`Explicit`]／[`Implicit`]。
//! 欄位清單會分別用於長度計算與實際寫入；同一組規則下必須保持一致，不能依呼叫
//! 次數改變欄位。這些 helper 不配置額外的欄位清單。
//! 所有資料處理都是變動時間，只適用公開的編碼結構，沒有常數時間替代方法。

mod fields;
mod sequence;
mod tagging;

pub use fields::Fields;
pub use sequence::SequenceFields;
pub use tagging::{Explicit, Implicit};
