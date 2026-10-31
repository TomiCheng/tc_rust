use core::fmt;

/// DSA 簽章編碼的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DsaEncodingError {
    /// r 或 s 為負或不小於群的階。
    ValueOutOfRange,
    /// 編碼的長度或格式不對，或不是 DER。
    Malformed,
    /// 輸出緩衝區放不下編碼。
    OutputTooShort,
}

impl fmt::Display for DsaEncodingError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ValueOutOfRange => "Value out of range",
            Self::Malformed => "Malformed signature",
            Self::OutputTooShort => "the output buffer is too small",
        })
    }
}

impl core::error::Error for DsaEncodingError {}
