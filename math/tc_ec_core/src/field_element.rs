//! 體元素的最小共通層。
//!
//! Fp 與 F2m 都需要加、減、乘、平方與反元素，但只有 Fp 需要平方根，
//! F2m 則需要 trace 與解二次方程；共通運算留在本 trait，兩組專屬運算分到
//! `PrimeFieldElement` 與 `BinaryFieldElement`，避免用無意義的方法填滿單一介面。
//!
//! # Draft API
//!
//! 此簽章是 step 1 草案，預期會在 step 3 接受真實 Fp 實作壓力後大改；
//! 請勿視為穩定 API。

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
