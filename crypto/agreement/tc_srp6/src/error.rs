use core::fmt;

/// BC 的 SRP-6a 類別會拒絕的情況。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Srp6Error {
    /// 在 `init` 之前就要求計算。
    NotInitialized,
    /// 群組不合格：N 不是大於 3 的奇數，或 g 不在 `[2, N - 2]`。
    InvalidGroup,
    /// 對方的公開值除以 N 餘 0。
    InvalidPublicValue,
    /// 前面的步驟還沒做，缺少這一步需要的值（A、B、S、M1 或 M2）。
    MissingValues,
}

impl fmt::Display for Srp6Error {
    /// 寫出錯誤訊息，盡量沿用 BC 的措辭。常數時間；輸出時間取決於 formatter。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "SRP-6 is not initialised",
            Self::InvalidGroup => "invalid SRP-6 group parameters",
            Self::InvalidPublicValue => "Invalid public value: 0",
            Self::MissingValues => "some data are missing from the previous operations",
        })
    }
}

impl core::error::Error for Srp6Error {}
