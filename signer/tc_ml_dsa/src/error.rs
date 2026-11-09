use core::fmt;

/// ML-DSA 會拒絕的金鑰、參數或操作。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlDsaError {
    /// 在 `init` 之前就要求簽章或驗章。
    NotInitialized,
    /// 以公鑰簽章。
    NotForSigning,
    /// 以私鑰驗章。
    NotForVerification,
    /// 金鑰的參數組與 signer 的不同。
    ParameterMismatch,
    /// 金鑰編碼的長度不對。
    InvalidKeyLength,
    /// 情境字串超過 255 bytes。
    ContextTooLong,
    /// 簽章緩衝區太短。
    OutputTooShort,
    /// 拒絕取樣 1000 次仍沒有簽章。
    SigningFailed,
}

impl fmt::Display for MlDsaError {
    /// 寫出錯誤訊息。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the signer is not initialized",
            Self::NotForSigning => "MLDsaSigner not initialised for signature generation.",
            Self::NotForVerification => "MLDsaSigner not initialised for verification",
            Self::ParameterMismatch => "Mismatching key parameter set",
            Self::InvalidKeyLength => "invalid encoding",
            Self::ContextTooLong => "context too long",
            Self::OutputTooShort => "the signature buffer is too short",
            Self::SigningFailed => "no signature after 1000 attempts",
        })
    }
}

impl core::error::Error for MlDsaError {}
