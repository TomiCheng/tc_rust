use std::error::Error;
use std::fmt;
use std::io;

/// 產生 PEM 物件失敗，對應 BC 的 `PemGenerationException`。
#[derive(Debug)]
pub struct PemGenerationError {
    message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl PemGenerationError {
    /// 常數時間：只搬移欄位。
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// 帶著造成失敗的錯誤，對應 BC 的 `innerException`。
    /// 常數時間：只搬移欄位。
    pub fn with_source(
        message: impl Into<String>,
        source: impl Into<Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// 常數時間。
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PemGenerationError {
    /// 變動時間：輸出長度依訊息而定，只能用於公開值。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for PemGenerationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<PemGenerationError> for io::Error {
    fn from(error: PemGenerationError) -> Self {
        io::Error::other(error)
    }
}
