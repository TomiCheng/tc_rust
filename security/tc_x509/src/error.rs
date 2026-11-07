use core::error::Error;
use core::fmt;

use tc_algo_v2::AlgoError;
use tc_asn1::Asn1Error;

// The error of this crate, wrapping those of the crates underneath
#[derive(Debug)]
#[non_exhaustive]
pub enum X509Error {
    Algo(AlgoError),
    Asn1(Asn1Error),
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algo(_) => f.write_str("algorithm failure"),
            Self::Asn1(_) => f.write_str("ASN.1 failure"),
        }
    }
}

impl Error for X509Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Algo(error) => Some(error),
            Self::Asn1(error) => Some(error),
        }
    }
}

impl From<AlgoError> for X509Error {
    fn from(error: AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<Asn1Error> for X509Error {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}
