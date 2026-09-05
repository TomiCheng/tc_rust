//! 體元素的最小共通層。
//!
//! Fp 與 F2m 都需要加、減、乘、平方與反元素，但只有 Fp 需要平方根，
//! F2m 則需要 trace 與解二次方程；共通運算留在本 trait，兩組專屬運算分到
//! `PrimeFieldElement` 與 `BinaryFieldElement`，避免用無意義的方法填滿單一介面。
//!
//! # API 狀態
//!
//! Step 3 已用 Montgomery Fp 元素驗證此簽章；介面仍在拆分期，請勿視為
//! 穩定 API。

/// Fp 與 F2m 體元素共享的運算介面。
pub trait FieldElement: Clone + Eq {
    /// 產生同一個體域中的加法單位元。
    fn zero(&self) -> Self;

    /// 產生同一個體域中的乘法單位元。
    fn one(&self) -> Self;

    /// 是否為加法單位元。
    fn is_zero(&self) -> bool;

    /// 是否為乘法單位元。
    fn is_one(&self) -> bool;

    /// 體域加法。
    fn add(&self, rhs: &Self) -> Self;

    /// 體域減法。
    fn sub(&self, rhs: &Self) -> Self;

    /// 體域乘法。
    fn mul(&self, rhs: &Self) -> Self;

    /// 體域平方。
    fn square(&self) -> Self;

    /// 加法反元素。
    fn negate(&self) -> Self;

    /// 乘法反元素；零沒有反元素。
    fn invert(&self) -> Option<Self>;
}
