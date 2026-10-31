use core::error::Error;
use core::fmt;

// After std::io::Error: the kind and the underlying error are kept apart, so new kinds and
// underlying errors can be added without breaking compatibility
#[derive(Debug)]
pub struct AlgoError {
    kind: ErrorKind,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl AlgoError {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

// Display writes only the kind; the underlying error comes from source(), so error chains do not
// print it twice
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
