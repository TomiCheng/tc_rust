use core::fmt;
use tc_dsa::DsaEncodingError;

/// SM2 的金鑰、密文或緩衝區錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sm2Error {
    /// 在 `init` 之前就要求運算。
    NotInitialized,
    /// 加密要公鑰、解密要私鑰，給錯了方向。
    WrongKeyForDirection,
    /// 公鑰 Q 乘上餘因子後是無窮遠點。
    InvalidKey,
    /// 曲線沒有階 n。
    MissingOrder,
    /// 輸入是空的。
    EmptyInput,
    /// 輸出緩衝區短於 `output_size`。
    OutputTooShort,
    /// 密文短於 C1 加 C3。
    CiphertextTooShort,
    /// C1 不是曲線上的點，或乘上餘因子後是無窮遠點。
    InvalidPoint,
    /// C3 不符：密文被竄改或金鑰不對。
    InvalidCiphertext,
    /// 金鑰交換的金鑰不在同一個網域。
    DomainMismatch,
    /// 使用者 ID 不短於 8192 位元組，放不進 16 位元的 ENTL。
    InvalidUserId,
    /// 共享點 U 是無窮遠點。
    InvalidAgreement,
    /// 發起方確認時沒有給回應方的標籤。
    MissingConfirmationTag,
    /// 回應方的確認標籤不符。
    ConfirmationMismatch,
    /// 簽章要私鑰、驗證要公鑰，給錯了。
    WrongKeyForSigning,
    /// 簽章的私鑰不在 `[1, n - 2]`，1 + d 沒有反元素。
    PrivateKeyOutOfRange,
    /// 簽章無法編碼，例如輸出緩衝區太短。
    Encoding(DsaEncodingError),
}

impl fmt::Display for Sm2Error {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "SM2 engine not initialised",
            Self::WrongKeyForDirection => {
                "SM2 needs a public key for encryption and a private key for decryption"
            }
            Self::InvalidKey => "invalid key: [h]Q at infinity",
            Self::MissingOrder => "the curve has no order",
            Self::EmptyInput => "input buffer too short",
            Self::OutputTooShort => "output buffer too short",
            Self::CiphertextTooShort => "data too short",
            Self::InvalidPoint => "[h]C1 at infinity or not on the curve",
            Self::InvalidCiphertext => "invalid cipher text",
            Self::DomainMismatch => "the keys have different domain parameters",
            Self::InvalidUserId => "SM2 user ID must be less than 2^16 bits long",
            Self::InvalidAgreement => "the shared point U is infinity",
            Self::MissingConfirmationTag => "if initiating, confirmationTag must be set",
            Self::ConfirmationMismatch => "confirmation tag mismatch",
            Self::WrongKeyForSigning => {
                "SM2 needs a private key for signing and a public key for verification"
            }
            Self::PrivateKeyOutOfRange => "SM2 private key out of range",
            Self::Encoding(error) => return write!(f, "unable to encode signature: {error}"),
        })
    }
}

impl core::error::Error for Sm2Error {}
