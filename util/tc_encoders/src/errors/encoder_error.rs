use core::fmt;

/// 編碼與解碼的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EncoderError {
    /// 輸出緩衝區不夠大。
    BufferTooSmall,
    /// 去掉空白後的長度不是區塊的整數倍。
    InvalidLength,
    /// 出現字元表以外的字元。
    InvalidCharacter,
    /// 填充字元的位置或數量不對。
    InvalidPadding,
}

impl fmt::Display for EncoderError {
    /// 變動時間：只依錯誤種類分支。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooSmall => "output buffer too small",
            Self::InvalidLength => "invalid encoded length",
            Self::InvalidCharacter => "invalid character",
            Self::InvalidPadding => "invalid padding",
        })
    }
}

impl core::error::Error for EncoderError {}
