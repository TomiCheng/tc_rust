use core::fmt;
use tc_gost3410_key::Gost3410Error;

/// `Gost3410Signer` 的錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gost3410SignerError {
    /// 在 `init` 之前就要求簽章或驗證。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 金鑰或參數不合格。
    InvalidKey(Gost3410Error),
}

impl fmt::Display for Gost3410SignerError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("GOST3410 private key required for signing"),
            Self::NotForVerifying => f.write_str("GOST3410 public key required for verification"),
            Self::InvalidKey(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for Gost3410SignerError {}
