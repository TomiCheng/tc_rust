use core::convert::Infallible;
use core::fmt;

/// `PssSigner` 的錯誤：`E` 是 RSA 引擎的錯誤，`C` 是訊息雜湊的錯誤，例如預先雜湊的長度
/// 不對。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PssSignerError<E, C = Infallible> {
    /// 在 `init` 之前就使用。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 金鑰太短，放不下雜湊與 salt。
    KeyTooSmall,
    /// 訊息雜湊失敗。
    Digest(C),
    /// RSA 引擎失敗。
    Cipher(E),
}

impl<E: fmt::Display, C: fmt::Display> fmt::Display for PssSignerError<E, C> {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => f.write_str("signing requires a private key"),
            Self::NotForVerifying => f.write_str("verification requires a public key"),
            Self::KeyTooSmall => f.write_str("key too small for specified hash and salt lengths"),
            Self::Digest(error) => error.fmt(f),
            Self::Cipher(error) => error.fmt(f),
        }
    }
}

impl<E: core::error::Error, C: core::error::Error> core::error::Error for PssSignerError<E, C> {}
