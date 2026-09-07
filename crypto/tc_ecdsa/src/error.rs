use core::fmt;

/// ECDSA 金鑰、算術或編碼錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaError {
    /// 曲線沒有提供子群階。
    MissingCurveOrder,
    /// 子群階必須是大於一的奇數。
    InvalidCurveOrder,
    /// 私密純量不在 `[1, n - 1]`。
    InvalidPrivateKey,
    /// 基點無效或是無窮遠點。
    InvalidGenerator,
    /// 公開點無效或是無窮遠點。
    InvalidPublicKey,
    /// 位元序列無法放入曲線的固定寬度純量。
    ScalarOutOfRange,
    /// 曲線座標無法轉成其純量整數型別。
    CoordinateOutOfRange,
    /// 簽章分量沒有乘法反元素。
    NotInvertible,
    /// Plain 編碼長度不正確。
    InvalidEncodingLength,
    /// Plain 編碼中的 `r` 或 `s` 不在 `[1, n - 1]`。
    InvalidSignatureValue,
    /// 底層曲線演算法拒絕輸入或結果。
    CurveOperation,
}

impl fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingCurveOrder => "curve order is missing",
            Self::InvalidCurveOrder => "curve order must be an odd integer greater than one",
            Self::InvalidPrivateKey => "private scalar is outside [1, n - 1]",
            Self::InvalidGenerator => "generator is invalid or is the point at infinity",
            Self::InvalidPublicKey => "public key is invalid or is the point at infinity",
            Self::ScalarOutOfRange => "integer does not fit the curve scalar type",
            Self::CoordinateOutOfRange => "field coordinate does not fit the curve scalar type",
            Self::NotInvertible => "signature scalar is not invertible modulo the curve order",
            Self::InvalidEncodingLength => "plain signature encoding has an invalid length",
            Self::InvalidSignatureValue => "signature component is outside [1, n - 1]",
            Self::CurveOperation => "elliptic-curve operation failed",
        })
    }
}

impl core::error::Error for EcdsaError {}
