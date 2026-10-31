use core::error::Error;
use core::fmt;

// 照 std::io::Error：種類與底層錯誤分開，日後加種類或帶上底層錯誤都不破壞相容性
#[derive(Debug)]
pub struct AlgoError {
    kind: ErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl AlgoError {
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

// Display 只寫種類；底層錯誤由 source() 交出，不重複寫進訊息
impl fmt::Display for AlgoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

impl Error for AlgoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    UnknownDigest,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::UnknownDigest => f.write_str("unknown digest algorithm"),
        }
    }
}
