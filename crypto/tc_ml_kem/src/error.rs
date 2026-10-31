use core::fmt;

/// ML-KEM 會拒絕的金鑰、參數或緩衝區。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemError {
    /// 在 `init` 之前就要求封裝或解封裝。
    NotInitialized,
    /// 金鑰的參數組與封裝方、解封裝方的不同。
    ParameterMismatch,
    /// 金鑰編碼的長度不對。
    InvalidKeyLength,
    /// 封裝金鑰有不小於 q 的係數。
    InvalidPublicKey,
    /// 解封裝金鑰裡的 H(ek) 不符。
    InvalidPrivateKey,
    /// 封裝的長度不對。
    InvalidEncapsulationLength,
    /// 共享秘密緩衝區的長度不對。
    InvalidSecretLength,
}

impl fmt::Display for MlKemError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the KEM is not initialized",
            Self::ParameterMismatch => "Mismatching key parameter set",
            Self::InvalidKeyLength => "Invalid length",
            Self::InvalidPublicKey => "Modulus check failed",
            Self::InvalidPrivateKey => "Hash check failed",
            Self::InvalidEncapsulationLength => "the encapsulation has the wrong length",
            Self::InvalidSecretLength => "the secret buffer has the wrong length",
        })
    }
}

impl core::error::Error for MlKemError {}
