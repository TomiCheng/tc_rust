//! 體元素的最小共通層。
//!
//! Fp 與 F2m 都需要加、減、乘、平方、平方根與反元素。零與一的工廠留在
//! `Curve`，因為執行期欄位需要由曲線提供模數或約簡參數。F2m 的平方根是
//! 便宜的 Frobenius power，Fp 則可能沒有平方根，因此共通簽章仍以 `Option` 表達。
//! trace 與 half-trace 才留在 `BinaryFieldElement` 專屬層。
//!
//! # API 狀態
//!
//! Step 3 已用 Montgomery Fp 元素驗證此簽章；介面仍在拆分期，請勿視為
//! 穩定 API。

/// Fp 與 F2m 體元素共享的運算介面。
pub trait FieldElement: Clone + Eq {
    /// 是否為加法單位元。
    fn is_zero(&self) -> bool;

    /// 是否為乘法單位元。
    fn is_one(&self) -> bool;

    /// 體域加法。
    fn add(&self, rhs: &Self) -> Self;

    /// 體域減法。
    fn subtract(&self, rhs: &Self) -> Self;

    /// 體域乘法。
    fn multiply(&self, rhs: &Self) -> Self;

    /// 體域平方。
    fn square(&self) -> Self;

    /// 若存在，回傳本元素的一個平方根。
    fn sqrt(&self) -> Option<Self>;

    /// 加法反元素。
    fn negate(&self) -> Self;

    /// 乘法反元素；零沒有反元素。
    fn invert(&self) -> Option<Self>;

    /// SEC 1 FE2OSP 的長度，即 BC 的 `GetEncodedLength`：`⌈體域位元數 / 8⌉` 位元組。
    fn encoded_length(&self) -> usize;

    /// SEC 1 FE2OSP，即 BC 的 `EncodeTo`：以 big-endian 寫入恰為
    /// [`encoded_length`](Self::encoded_length) 位元組的 `output`；長度不符時 panic。
    /// ECDH 的共享秘密與 ECDSA 的 r 都由此取得 x 座標。
    fn encode_to(&self, output: &mut [u8]);
}
