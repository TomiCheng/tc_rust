use core::fmt;

/// `Iso9796d2Signer` 與 `Iso9796d2PssSigner` 的錯誤：`E` 是 RSA 引擎的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Iso9796d2Error<E> {
    /// 在 `init` 之前就使用。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證或還原。
    NotForVerifying,
    /// 雜湊沒有 ISO/IEC 10118 代號，無法標明結尾；可改用隱含結尾。
    NoTrailer,
    /// 金鑰太短，放不下雜湊、salt 與結尾。
    KeyTooSmall,
    /// 簽章解不出 ISO 9796-2 的區塊。
    MalformedSignature,
    /// 簽章標明了結尾，但雜湊沒有代號可比對。
    UnrecognisedTrailer,
    /// 簽章的結尾標明另一種雜湊。
    TrailerMismatch(u16),
    /// 驗證的簽章與 `update_with_recovered_message` 的不同。
    DifferentSignature,
    /// RSA 引擎失敗。
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for Iso9796d2Error<E> {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("signing requires a private key"),
            Self::NotForVerifying => f.write_str("verification requires a public key"),
            Self::NoTrailer => f.write_str("no valid trailer"),
            Self::KeyTooSmall => f.write_str("key too small for the digest and salt"),
            Self::MalformedSignature => f.write_str("malformed signature"),
            Self::UnrecognisedTrailer => f.write_str("unrecognised hash in signature"),
            Self::TrailerMismatch(trailer) => {
                write!(
                    f,
                    "signer initialised with wrong digest for trailer {trailer}"
                )
            }
            Self::DifferentSignature => {
                f.write_str("updateWithRecoveredMessage called on different signature")
            }
            Self::Cipher(error) => error.fmt(f),
        }
    }
}

impl<E: core::error::Error> core::error::Error for Iso9796d2Error<E> {}
