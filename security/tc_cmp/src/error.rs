use std::{fmt, io};

#[derive(Debug)]
#[non_exhaustive]
pub enum CmpError {
    Asn1(tc_asn1::Asn1Error),
    Algo(tc_algo::AlgoError),
    Crmf(tc_crmf::CrmfError),
    X509(tc_x509::X509Error),
    Io(io::Error),
    Invalid(&'static str),
}

impl fmt::Display for CmpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(error) => write!(formatter, "CMP ASN.1 error: {error}"),
            Self::Algo(error) => write!(formatter, "CMP algorithm error: {error}"),
            Self::Crmf(error) => write!(formatter, "CMP CRMF error: {error}"),
            Self::X509(error) => write!(formatter, "CMP X.509 error: {error}"),
            Self::Io(error) => write!(formatter, "CMP I/O error: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CmpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Asn1(error) => Some(error),
            Self::Algo(error) => Some(error),
            Self::Crmf(error) => Some(error),
            Self::X509(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Invalid(_) => None,
        }
    }
}

impl From<tc_asn1::Asn1Error> for CmpError {
    fn from(error: tc_asn1::Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<tc_algo::AlgoError> for CmpError {
    fn from(error: tc_algo::AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<tc_crmf::CrmfError> for CmpError {
    fn from(error: tc_crmf::CrmfError) -> Self {
        Self::Crmf(error)
    }
}

impl From<tc_x509::X509Error> for CmpError {
    fn from(error: tc_x509::X509Error) -> Self {
        Self::X509(error)
    }
}

impl From<io::Error> for CmpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
