use core::error::Error;
use core::fmt;

use tc_algo::AlgoError;
use tc_asn1::Asn1Error;
use tc_asn1_cmp::PkiFailureInfo;
use tc_cms::CmsError;
use tc_x509::X509Error;

// 這個 crate 的錯誤，包住底層 crate 的錯誤
#[derive(Debug)]
#[non_exhaustive]
pub enum TspError {
    Algo(AlgoError),
    Asn1(Asn1Error),
    X509(X509Error),
    Cms(CmsError),
    // token 的結構不是 RFC 3161 的，BC 建構 TimeStampToken 時的 TspValidationException
    InvalidToken(&'static str),
    // 驗證沒過，BC 的 TspValidationException
    Validation(&'static str),
    // 請求被拒，帶著回應要寫的 PKIFailureInfo
    Rejected(PkiFailureInfo),
}

impl fmt::Display for TspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algo(error) => write!(f, "{error}"),
            Self::Asn1(error) => write!(f, "{error}"),
            Self::X509(error) => write!(f, "{error}"),
            Self::Cms(error) => write!(f, "{error}"),
            Self::InvalidToken(reason) => write!(f, "invalid time-stamp token: {reason}"),
            Self::Validation(reason) => write!(f, "time-stamp validation failed: {reason}"),
            Self::Rejected(info) => write!(f, "time-stamp request rejected: {:#x}", info.bits()),
        }
    }
}

impl Error for TspError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Algo(error) => Some(error),
            Self::Asn1(error) => Some(error),
            Self::X509(error) => Some(error),
            Self::Cms(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AlgoError> for TspError {
    fn from(error: AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<Asn1Error> for TspError {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<X509Error> for TspError {
    fn from(error: X509Error) -> Self {
        Self::X509(error)
    }
}

impl From<CmsError> for TspError {
    fn from(error: CmsError) -> Self {
        Self::Cms(error)
    }
}
