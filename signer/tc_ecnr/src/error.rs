use core::fmt;

/// BC 的 `ECNRSigner` 會拒絕的簽章或驗證。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcnrError {
    /// 在 `init` 之前就要求簽章或驗證。
    NotInitialized,
    /// 金鑰的曲線沒有階，或階是偶數。
    MissingOrder,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 訊息的位元數比群的階多。
    InputTooLarge,
}

impl fmt::Display for EcnrError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the signer is not initialized",
            Self::MissingOrder => "the curve has no odd order",
            Self::NotForSigning => "not initialised for signing",
            Self::NotForVerifying => "not initialised for verifying",
            Self::InputTooLarge => "input too large for ECNR key.",
        })
    }
}

impl core::error::Error for EcnrError {}
