use core::fmt;

/// 帶 KDF 的協商的錯誤：`A` 是底層協商的錯誤，`K` 是 KDF 的錯誤。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgreementWithKdfError<A, K> {
    /// 在 `init` 之前就要求協商。
    NotInitialized,
    /// 輸出緩衝區短於導出的金鑰。
    BufferTooSmall,
    /// 底層的協商失敗。
    Agreement(A),
    /// KDF 失敗。
    Kdf(K),
}

impl<A: fmt::Display, K: fmt::Display> fmt::Display for AgreementWithKdfError<A, K> {
    /// 寫出錯誤訊息；包住的錯誤沿用它自己的訊息。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("Agreement algorithm not initialised"),
            Self::BufferTooSmall => f.write_str("the output buffer is too small"),
            Self::Agreement(error) => error.fmt(f),
            Self::Kdf(error) => error.fmt(f),
        }
    }
}

impl<A: core::error::Error, K: core::error::Error> core::error::Error
    for AgreementWithKdfError<A, K>
{
}
