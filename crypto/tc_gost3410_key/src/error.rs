use core::fmt;

/// GOST R 34.10-94 參數、金鑰與產生器的錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gost3410Error {
    /// 在 `init` 之前就要求產生。
    NotInitialized,
    /// p 不是大於 2 的奇數。
    InvalidModulus,
    /// q 不是大於 2、小於 p 的奇數。
    InvalidOrder,
    /// a 不在 `[2, p − 1]`。
    InvalidGenerator,
    /// 公鑰 y 不在 `[1, p − 1]`。
    InvalidPublicKey,
    /// 私鑰 x 不在 `[1, q − 1]`，或超過 256 位元。
    InvalidPrivateKey,
    /// 參數產生器只支援 512 與 1024 位元。
    InvalidSize,
    /// 參數產生器的程序只有 1（16 位元的 A、B）與 2（32 位元的 A'、B'）。
    InvalidProcedure,
}

impl fmt::Display for Gost3410Error {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the generator is not initialized",
            Self::InvalidModulus => "p must be an odd number above 2",
            Self::InvalidOrder => "q must be an odd number above 2 and below p",
            Self::InvalidGenerator => "a must lie in [2, p - 1]",
            Self::InvalidPublicKey => "Invalid y for GOST3410 public key",
            Self::InvalidPrivateKey => "Invalid x for GOST3410 private key",
            Self::InvalidSize => "Ooops! key size 512 or 1024 bit.",
            Self::InvalidProcedure => "the procedure must be 1 or 2",
        })
    }
}

impl core::error::Error for Gost3410Error {}
