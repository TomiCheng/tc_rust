use std::{fmt, io};

#[derive(Debug)]
#[non_exhaustive]
pub enum CrmfError {
    Asn1(tc_asn1::Asn1Error),
    Algo(tc_algo::AlgoError),
    X509(tc_x509::X509Error),
    Io(io::Error),
    Invalid(&'static str),
    IterationCountOutsideInt32,
    IterationCountBelowOne,
    IterationCountExceedsLimit { count: i32, max: i32 },
    Random(String),
}

impl fmt::Display for CrmfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(error) => write!(f, "CRMF ASN.1 error: {error}"),
            Self::Algo(error) => write!(f, "CRMF algorithm error: {error}"),
            Self::X509(error) => write!(f, "CRMF X.509 error: {error}"),
            Self::Io(error) => write!(f, "CRMF I/O error: {error}"),
            Self::Invalid(message) => f.write_str(message),
            Self::IterationCountOutsideInt32 => f.write_str("iteration count outside Int32 range"),
            Self::IterationCountBelowOne => f.write_str("iteration count less than 1"),
            Self::IterationCountExceedsLimit { count, max } => {
                write!(f, "iteration count exceeds limit ({count} > {max})")
            }
            Self::Random(error) => write!(f, "CRMF random source failed: {error}"),
        }
    }
}

impl std::error::Error for CrmfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Asn1(error) => Some(error),
            Self::Algo(error) => Some(error),
            Self::X509(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<tc_asn1::Asn1Error> for CrmfError {
    fn from(error: tc_asn1::Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<tc_algo::AlgoError> for CrmfError {
    fn from(error: tc_algo::AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<tc_x509::X509Error> for CrmfError {
    fn from(error: tc_x509::X509Error) -> Self {
        Self::X509(error)
    }
}

impl From<io::Error> for CrmfError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
