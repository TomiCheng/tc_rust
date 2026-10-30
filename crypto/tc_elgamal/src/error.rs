use core::fmt;
use tc_dh_key::DhError;

/// ElGamal 的參數、金鑰或區塊錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElGamalError {
    /// 在 `init` 之前就要求運算或產生。
    NotInitialized,
    /// 參數不合格，或產生器的設定不合格，細節同 DH。
    InvalidParameters(DhError),
    /// 加密要公鑰、解密要私鑰，給錯了方向。
    WrongKeyForDirection,
    /// 公鑰 y 不在 `[2, p - 2]`，或私鑰 x 大於 p − 2。
    InvalidKey,
    /// 明文超過輸入區塊。
    InputTooLarge,
    /// 明文是 0：φ 會是 0，解密時被當成弱值拒絕，所以加密時就拒絕。
    InputTooSmall,
    /// 密文長度不是兩倍的 p 位元組數。
    InvalidCiphertextLength,
    /// 密文的 γ 或 φ 不在 `[2, p - 2]`。
    WeakCiphertext,
    /// 輸出緩衝區短於輸出區塊。
    OutputTooShort,
}

impl From<DhError> for ElGamalError {
    /// 包起 DH 的參數錯誤。常數時間。
    fn from(error: DhError) -> Self {
        Self::InvalidParameters(error)
    }
}

impl fmt::Display for ElGamalError {
    /// 寫出錯誤訊息。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("ElGamal engine not initialised"),
            Self::InvalidParameters(error) => write!(f, "invalid ElGamal parameters: {error}"),
            Self::WrongKeyForDirection => f.write_str(
                "ElGamal needs a public key for encryption and a private key for decryption",
            ),
            Self::InvalidKey => f.write_str("invalid ElGamal key"),
            Self::InputTooLarge => f.write_str("input too large for ElGamal cipher"),
            Self::InputTooSmall => f.write_str("input too small for ElGamal cipher"),
            Self::InvalidCiphertextLength => {
                f.write_str("input is the wrong size for ElGamal cipher")
            }
            Self::WeakCiphertext => f.write_str("ElGamal ciphertext element is weak"),
            Self::OutputTooShort => f.write_str("output buffer too short for ElGamal cipher"),
        }
    }
}

impl core::error::Error for ElGamalError {}
