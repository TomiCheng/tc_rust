use crate::DsaEncodingError;
use core::fmt;

/// `DsaDigestSigner` 的錯誤：`E` 是底層 DSA 的錯誤。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DsaDigestSignerError<E> {
    /// 在 `init` 之前就使用。
    NotInitialized,
    /// 以公鑰初始化，卻要求簽章。
    NotForSigning,
    /// 以私鑰初始化，卻要求驗證。
    NotForVerifying,
    /// 底層 DSA 失敗。
    Dsa(E),
    /// 簽章無法編碼，例如輸出緩衝區太短。
    Encoding(DsaEncodingError),
}

impl<E: fmt::Display> fmt::Display for DsaDigestSignerError<E> {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("the signer is not initialized"),
            Self::NotForSigning => {
                f.write_str("DsaDigestSigner not initialized for signature generation.")
            }
            Self::NotForVerifying => {
                f.write_str("DsaDigestSigner not initialized for verification")
            }
            Self::Dsa(error) => error.fmt(f),
            Self::Encoding(error) => write!(f, "unable to encode signature: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for DsaDigestSignerError<E> {}
