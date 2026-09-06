//! SEC 點編碼共用錯誤。

/// 寫入 SEC 點編碼時發生的錯誤。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PointEncodeError {
    /// 呼叫端提供的輸出緩衝不足。
    OutputTooShort { required: usize, available: usize },
}

impl core::fmt::Display for PointEncodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutputTooShort {
                required,
                available,
            } => write!(
                f,
                "point encoding requires {required} bytes, but output has {available}"
            ),
        }
    }
}

impl core::error::Error for PointEncodeError {}
