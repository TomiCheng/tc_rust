use core::fmt;

/// BC 的 `ECVkoAgreement` 會拒絕的情況。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcVkoError {
    /// 在 `init` 之前就要求協商。
    NotInitialized,
    /// 曲線沒有階 n。
    MissingOrder,
    /// 對方的公鑰與私鑰不在同一個網域。
    DomainMismatch,
    /// 對方的公鑰不是曲線上的有限點。
    InvalidPublicKey,
    /// 共享點是無窮遠點，例如 UKM 為零。
    InvalidAgreement,
    /// 輸出緩衝區短於協商結果。
    BufferTooSmall,
}

impl fmt::Display for EcVkoError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "Agreement algorithm not initialised",
            Self::MissingOrder => "the curve has no order",
            Self::DomainMismatch => "ECVKO public key has wrong domain parameters",
            Self::InvalidPublicKey => "Infinity is not a valid public key for ECVKO",
            Self::InvalidAgreement => "Infinity is not a valid agreement value for ECVKO",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for EcVkoError {}
