use core::fmt;

/// `Dstu4145Signer` 的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Dstu4145Error {
    /// 在 `init` 之前就簽章或驗證。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 曲線沒有階 n。
    MissingOrder,
}

impl fmt::Display for Dstu4145Error {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the signer is not initialized",
            Self::NotForSigning => "EC private key required for signing",
            Self::NotForVerifying => "EC public key required for verification",
            Self::MissingOrder => "the curve has no order",
        })
    }
}

impl core::error::Error for Dstu4145Error {}
