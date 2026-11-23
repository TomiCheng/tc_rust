use std::error::Error;
use std::fmt;

use tc_x509::X509Error;

// BC 的 PkixCertPathValidatorReason
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ValidatorReason {
    Unspecified,
    Expired,
    NotYetValid,
    Revoked,
    UndeterminedRevocationStatus,
    InvalidSignature,
    AlgorithmConstrained,
    NameChaining,
    InvalidKeyUsage,
    InvalidPolicy,
    NoTrustAnchor,
    UnrecognizedCriticalExtension,
    NotCaCertificate,
    PathTooLong,
    InvalidName,
    LimitExceeded,
}

type Source = Box<dyn Error + Send + Sync>;

// BC 的 PkixCertPathValidatorException：index 是出錯的憑證在路徑裡的位置，None 對應 BC 的 -1
#[derive(Debug)]
pub struct CertPathValidatorError {
    message: String,
    index: Option<usize>,
    reason: ValidatorReason,
    source: Option<Source>,
}

impl CertPathValidatorError {
    pub fn new(message: impl Into<String>, index: Option<usize>, reason: ValidatorReason) -> Self {
        Self {
            message: message.into(),
            index,
            reason,
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl Into<Source>) -> Self {
        self.source = Some(source.into());
        self
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn index(&self) -> Option<usize> {
        self.index
    }

    pub fn reason(&self) -> ValidatorReason {
        self.reason
    }
}

impl fmt::Display for CertPathValidatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CertPathValidatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

#[derive(Debug)]
pub enum PkixError {
    // BC 建構與 Validate 的 ArgumentException
    InvalidParameters(&'static str),
    Validator(CertPathValidatorError),
    // BC 的 PkixCertPathBuilderException
    Builder(String, Option<Source>),
    X509(X509Error),
}

impl fmt::Display for PkixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters(message) => f.write_str(message),
            Self::Validator(error) => error.fmt(f),
            Self::Builder(message, _) => f.write_str(message),
            Self::X509(error) => error.fmt(f),
        }
    }
}

impl Error for PkixError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Validator(error) => error.source(),
            Self::Builder(_, source) => source.as_deref().map(|source| source as _),
            Self::X509(error) => Some(error),
            Self::InvalidParameters(_) => None,
        }
    }
}

impl From<CertPathValidatorError> for PkixError {
    fn from(error: CertPathValidatorError) -> Self {
        Self::Validator(error)
    }
}

impl From<X509Error> for PkixError {
    fn from(error: X509Error) -> Self {
        Self::X509(error)
    }
}
