use core::fmt;

/// `X931Signer` 的錯誤：`E` 是 RSA 引擎的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X931SignerError<E> {
    /// 在 `init` 之前就使用。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 雜湊沒有 ISO/IEC 10118 代號，無法標明結尾；可改用隱含結尾。
    NoTrailer,
    /// 金鑰太短，放不下雜湊與結尾。
    KeyTooSmall,
    /// RSA 引擎失敗，例如模數的位元數不是 8 的倍數，使簽章區塊大於模數。
    Cipher(E),
}

impl<E: fmt::Display> fmt::Display for X931SignerError<E> {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("signing requires a private key"),
            Self::NotForVerifying => f.write_str("verification requires a public key"),
            Self::NoTrailer => f.write_str("no valid trailer"),
            Self::KeyTooSmall => f.write_str("key too small for the digest"),
            Self::Cipher(error) => error.fmt(f),
        }
    }
}

impl<E: core::error::Error> core::error::Error for X931SignerError<E> {}
