use std::{fmt, io};

use tc_asn1::Asn1Error;
use tc_asn1_ocsp::OcspResponseStatus;
use tc_x509::X509Error;

/// Errors from OCSP message generation or validation.
#[derive(Debug)]
#[non_exhaustive]
pub enum OcspError {
    Asn1(Asn1Error),
    Crypto(tc_algo::AlgoError),
    X509(X509Error),
    Io(io::Error),
    Malformed(&'static str),
    ResponseStatus(OcspResponseStatus),
    UnsupportedResponseType,
    UnsupportedCriticalExtension,
    InvalidSignature,
    UnauthorizedResponder,
    CertificateMismatch,
    NonceMismatch,
    InvalidTime,
}

impl fmt::Display for OcspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(error) => write!(f, "OCSP ASN.1 error: {error}"),
            Self::Crypto(error) => write!(f, "OCSP crypto error: {error}"),
            Self::X509(error) => write!(f, "OCSP X.509 error: {error}"),
            Self::Io(error) => write!(f, "OCSP I/O error: {error}"),
            Self::Malformed(message) => write!(f, "malformed OCSP message: {message}"),
            Self::ResponseStatus(status) => write!(f, "OCSP responder returned {status:?}"),
            Self::UnsupportedResponseType => f.write_str("unsupported OCSP response type"),
            Self::UnsupportedCriticalExtension => {
                f.write_str("unsupported critical OCSP extension")
            }
            Self::InvalidSignature => f.write_str("invalid OCSP signature"),
            Self::UnauthorizedResponder => f.write_str("unauthorized OCSP responder"),
            Self::CertificateMismatch => f.write_str("OCSP certificate identifier mismatch"),
            Self::NonceMismatch => f.write_str("OCSP nonce mismatch"),
            Self::InvalidTime => {
                f.write_str("OCSP response falls outside the accepted time window")
            }
        }
    }
}

impl std::error::Error for OcspError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Asn1(error) => Some(error),
            Self::Crypto(error) => Some(error),
            Self::X509(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<Asn1Error> for OcspError {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<tc_algo::AlgoError> for OcspError {
    fn from(error: tc_algo::AlgoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<X509Error> for OcspError {
    fn from(error: X509Error) -> Self {
        Self::X509(error)
    }
}

impl From<io::Error> for OcspError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
