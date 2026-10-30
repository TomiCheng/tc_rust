use core::fmt;
use tc_dh_key::DhError;

/// BC 的 DH 協商會拒絕的情況。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhAgreementError {
    /// 在 `init` 之前就要求協商。
    NotInitialized,
    /// 私鑰的參數不合格。
    InvalidParameters(DhError),
    /// 對方公鑰的參數與私鑰的不同（比較 p、g、q）。
    WrongParameters,
    /// 對方公鑰不合格：不在 `[2, p - 2]`、不在 q 階子群，或 p 太大。
    InvalidPublicKey(DhError),
    /// 共享秘密是 1。
    InvalidAgreement,
    /// 輸出緩衝區短於協商結果。
    BufferTooSmall,
}

impl fmt::Display for DhAgreementError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("Agreement algorithm not initialised"),
            Self::InvalidParameters(error) => {
                write!(f, "invalid Diffie-Hellman parameters: {error}")
            }
            Self::WrongParameters => f.write_str("Diffie-Hellman public key has wrong parameters."),
            Self::InvalidPublicKey(error) => {
                write!(f, "Diffie-Hellman public key is weak: {error}")
            }
            Self::InvalidAgreement => f.write_str("Shared key can't be 1"),
            Self::BufferTooSmall => f.write_str("the output buffer is too small"),
        }
    }
}

impl core::error::Error for DhAgreementError {}
