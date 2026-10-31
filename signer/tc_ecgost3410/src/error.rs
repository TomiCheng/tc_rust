use core::fmt;

/// BC 的 `ECGost3410Signer` 會拒絕的簽章或驗證。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcGost3410Error {
    /// 在 `init` 之前就要求簽章或驗證。
    NotInitialized,
    /// 金鑰的曲線沒有階，或階是偶數。
    MissingOrder,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
}

impl fmt::Display for EcGost3410Error {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the signer is not initialized",
            Self::MissingOrder => "the curve has no odd order",
            Self::NotForSigning => "not initialized for signing",
            Self::NotForVerifying => "not initialized for verification",
        })
    }
}

impl core::error::Error for EcGost3410Error {}
