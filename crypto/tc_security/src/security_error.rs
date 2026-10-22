use core::fmt::{self, Display, Formatter};

/// 工廠層的錯誤，對應 BC 的 `SecurityUtilityException`。
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityError {
    /// 名稱或 OID 不認得，或對應的 feature 沒開。
    UnknownDigest,
    /// 名稱、OID 或組合不認得。
    UnknownCipher,
    /// key wrap 的名稱或 OID 不認得。
    UnknownWrapper,
    /// MAC 的名稱或 OID 不認得。
    UnknownMac,
    /// 產生器的名稱或 OID 不認得。
    UnknownGenerator,
    /// key agreement 的名稱或 OID 不認得。
    UnknownAgreement,
    /// 產生金鑰的參數不屬於這個演算法，或數值不是它接受的。
    InvalidKeyGenParams,
    /// 產生器不產生這種金鑰：對稱金鑰的產生器呼叫了 `generate_key_pair`，或反過來。
    WrongGenerator,
    /// 參數不是這個演算法收的種類，例如 RSA 收到對稱金鑰、X25519 收到 X448 的金鑰。
    WrongParams,
}

impl Display for SecurityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDigest => f.write_str("digest not recognised"),
            Self::UnknownCipher => f.write_str("cipher not recognised"),
            Self::UnknownWrapper => f.write_str("wrapper not recognised"),
            Self::UnknownMac => f.write_str("MAC not recognised"),
            Self::UnknownGenerator => f.write_str("generator not recognised"),
            Self::UnknownAgreement => f.write_str("agreement not recognised"),
            Self::InvalidKeyGenParams => f.write_str("invalid key generation parameters"),
            Self::WrongGenerator => f.write_str("generator does not produce this kind of key"),
            Self::WrongParams => f.write_str("parameters do not fit this algorithm"),
        }
    }
}

impl core::error::Error for SecurityError {}
