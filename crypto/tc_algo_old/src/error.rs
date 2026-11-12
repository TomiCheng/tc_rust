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

    // Carries the error of the algorithm crate underneath, for source() to hand out
    #[allow(
        dead_code,
        reason = "unused when no algorithm that can fail is enabled"
    )]
    pub(crate) fn with_source(kind: ErrorKind, source: impl Error + Send + Sync + 'static) -> Self {
        Self {
            kind,
            source: Some(Box::new(source)),
        }
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
    UnknownGenerator,
    InvalidKeyGenParams,
    UnknownCipher,
    UnknownAgreement,
    UnknownMac,
    UnknownXof,
    UnknownWrapper,
    InvalidParams,
    DataLength,
    InvalidCiphertext,
    NotInitialized,
    XofOutputStarted,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::UnknownDigest => f.write_str("unknown digest algorithm"),
            ErrorKind::UnknownGenerator => f.write_str("unknown key generator"),
            ErrorKind::InvalidKeyGenParams => f.write_str("invalid key generation parameters"),
            ErrorKind::UnknownCipher => f.write_str("unknown cipher"),
            ErrorKind::UnknownAgreement => f.write_str("unknown key agreement"),
            ErrorKind::UnknownMac => f.write_str("unknown MAC"),
            ErrorKind::UnknownXof => f.write_str("unknown XOF"),
            ErrorKind::UnknownWrapper => f.write_str("unknown key wrapper"),
            ErrorKind::InvalidParams => f.write_str("invalid parameters for this algorithm"),
            ErrorKind::DataLength => f.write_str("input of the wrong length for this cipher"),
            ErrorKind::InvalidCiphertext => f.write_str("invalid ciphertext"),
            ErrorKind::NotInitialized => f.write_str("used before a successful init"),
            ErrorKind::XofOutputStarted => f.write_str("input after the XOF began its output"),
        }
    }
}
