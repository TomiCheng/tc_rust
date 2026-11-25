use core::fmt;

/// BC 的 ECMQV 協商會拒絕的情況。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcMqvError {
    /// 在 `init` 之前就要求協商。
    NotInitialized,
    /// 金鑰不在同一個網域：自己的兩把私鑰、自己的臨時公鑰，或對方的兩把公鑰。
    DomainMismatch,
    /// 曲線沒有階 n。
    MissingOrder,
    /// 對方的公鑰不是曲線上的有限點。
    InvalidPublicKey,
    /// 共享點是無窮遠點。
    InvalidAgreement,
    /// 輸出緩衝區短於協商結果。
    BufferTooSmall,
}

impl fmt::Display for EcMqvError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "Agreement algorithm not initialised",
            Self::DomainMismatch => "ECMQV key components have different domain parameters",
            Self::MissingOrder => "the curve has no order",
            Self::InvalidPublicKey => "the public key is not a valid point of the curve",
            Self::InvalidAgreement => "Infinity is not a valid agreement value for MQV",
            Self::BufferTooSmall => "the output buffer is too small",
        })
    }
}

impl core::error::Error for EcMqvError {}
