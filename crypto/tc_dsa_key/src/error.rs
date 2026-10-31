use core::fmt;

/// BC 的 DSA 參數類別與產生器會拒絕的參數或金鑰。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsaError {
    /// 在 `init` 之前就要求產生。
    NotInitialized,
    /// p 不是大於 2 的奇數。
    InvalidModulus,
    /// p 超過 16384 位元，BC `DsaMaxSize` 的預設上限。
    ModulusTooLarge,
    /// q 不是大於 2 的奇數，或不小於 p。
    InvalidOrder,
    /// g 不在 `[2, p - 1]`。
    InvalidGenerator,
    /// 公鑰 y 不在 `[2, p - 2]`，或不在 q 階子群裡。
    InvalidPublicKey,
    /// 私鑰 x 不在 `[1, q - 1]`。
    InvalidPrivateKey,
    /// FIPS 186-2 的 p 要在 512 到 1024 位元之間且是 64 的倍數。
    InvalidSize,
    /// FIPS 186-3 的 L 與 N 不是 (1024, 160)、(2048, 224)、(2048, 256) 或 (3072, 256)。
    InvalidLengths,
    /// 雜湊短於 N 位元，或 FIPS 186-2 用的不是 SHA-1。
    UnsuitableDigest,
    /// 質數檢定的 certainty 是 0。
    InvalidCertainty,
}

impl fmt::Display for DsaError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the generator is not initialized",
            Self::InvalidModulus => "p must be an odd integer above 2",
            Self::ModulusTooLarge => "DSA modulus out of range",
            Self::InvalidOrder => "q must be an odd integer above 2 and below p",
            Self::InvalidGenerator => "g must lie in [2, p - 1]",
            Self::InvalidPublicKey => "y value does not appear to be in correct group",
            Self::InvalidPrivateKey => "x must lie in [1, q - 1]",
            Self::InvalidSize => "size must be from 512 - 1024 and a multiple of 64",
            Self::InvalidLengths => {
                "L and N must be (1024, 160), (2048, 224 or 256) or (3072, 256)"
            }
            Self::UnsuitableDigest => "Digest output size too small for value of N",
            Self::InvalidCertainty => "certainty must be positive",
        })
    }
}

impl core::error::Error for DsaError {}
