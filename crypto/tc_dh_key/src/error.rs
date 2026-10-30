use core::fmt;

/// BC 的 DH 參數類別會拒絕的參數或金鑰。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhError {
    /// 在 `init` 之前就要求產生。
    NotInitialized,
    /// p 不是大於 2 的奇數。
    InvalidModulus,
    /// p 超過 16384 位元，BC `DHMaxSize` 的預設上限。
    ModulusTooLarge,
    /// g 不在 `[2, p - 2]`。
    InvalidGenerator,
    /// q 的位元數不小於 p 的，不可能是 p − 1 的因數。
    InvalidSubgroupOrder,
    /// m 不小於 p 的位元數；或 l 有設定卻不小於 p 的位元數、或小於 m。
    InvalidPrivateValueLength,
    /// 餘因子 j 小於 2。
    InvalidCofactor,
    /// 公鑰 y 不在 `[2, p - 2]`。
    InvalidPublicValue,
    /// 公鑰 y 不在 q 階子群裡。
    PublicValueOutsideSubgroup,
    /// 要產生的 p 少於 64 位元。
    InvalidSize,
    /// 質數檢定的 certainty 是 0。
    InvalidCertainty,
}

impl fmt::Display for DhError {
    /// 寫出錯誤訊息。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the generator is not initialized",
            Self::InvalidModulus => "field must be an odd prime",
            Self::ModulusTooLarge => "DH modulus out of range",
            Self::InvalidGenerator => "generator must in the range [2, p - 2]",
            Self::InvalidSubgroupOrder => "q too big to be a factor of (p-1)",
            Self::InvalidPrivateValueLength => {
                "private value length must be below the bit length of p and l not below m"
            }
            Self::InvalidCofactor => "subgroup factor must be >= 2",
            Self::InvalidPublicValue => "invalid DH public key",
            Self::PublicValueOutsideSubgroup => "value does not appear to be in correct group",
            Self::InvalidSize => "size < 64",
            Self::InvalidCertainty => "certainty must be at least 1",
        })
    }
}

impl core::error::Error for DhError {}
