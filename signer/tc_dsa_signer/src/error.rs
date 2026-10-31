use core::fmt;
use tc_dsa_key::DsaError;

/// `DsaSigner` 的錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsaSignerError {
    /// 在 `init` 之前就使用。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 金鑰或參數不合格。
    InvalidKey(DsaError),
}

impl fmt::Display for DsaSignerError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("DSA private key required for signing"),
            Self::NotForVerifying => f.write_str("DSA public key required for verification"),
            Self::InvalidKey(error) => write!(f, "invalid DSA key: {error}"),
        }
    }
}

impl core::error::Error for DsaSignerError {}
