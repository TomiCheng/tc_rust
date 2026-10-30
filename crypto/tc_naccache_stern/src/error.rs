use core::fmt;

/// Naccache-Stern 的參數、金鑰或區塊錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NaccacheSternError {
    /// 在 `init` 之前就要求運算或產生。
    NotInitialized,
    /// 解密要私鑰，給了公鑰。
    WrongKeyForDirection,
    /// 金鑰不合格：n 不是大於 2 的奇數、沒有小質數，或小質數不整除 φ(n)。
    InvalidKey,
    /// 明文超過輸入區塊。
    InputTooLarge,
    /// 密文長度不是 `n` 的位元數 / 8 + 1。
    InvalidCiphertextLength,
    /// 密文對某個小質數查不到對應的值，不是這把金鑰的密文。
    LookupFailed,
    /// 輸出緩衝區短於輸出區塊。
    OutputTooShort,
    /// 小質數的個數是奇數、少於 30，或超過內建的質數表。
    InvalidSmallPrimeCount,
    /// 強度扣掉 σ 與 48 位元後，放不下 p、q 的大質因數。
    StrengthTooSmall,
    /// 質數檢定的 certainty 是 0。
    InvalidCertainty,
}

impl fmt::Display for NaccacheSternError {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "NaccacheStern engine not initialised",
            Self::WrongKeyForDirection => "NaccacheStern decryption needs a private key",
            Self::InvalidKey => "invalid NaccacheStern key",
            Self::InputTooLarge => "input too large for Naccache-Stern cipher",
            Self::InvalidCiphertextLength => {
                "BlockLength does not match modulus for Naccache-Stern cipher"
            }
            Self::LookupFailed => "Lookup failed",
            Self::OutputTooShort => "output buffer too short for Naccache-Stern cipher",
            Self::InvalidSmallPrimeCount => {
                "countSmallPrimes must be an even number from 30 up to 100"
            }
            Self::StrengthTooSmall => "strength too small for the small primes",
            Self::InvalidCertainty => "certainty must be at least 1",
        })
    }
}

impl core::error::Error for NaccacheSternError {}
