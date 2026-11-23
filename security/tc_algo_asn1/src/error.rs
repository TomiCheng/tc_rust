use core::error::Error;
use core::fmt;

use tc_asn1::Asn1Error;

#[derive(Debug)]
#[non_exhaustive]
pub enum AlgoAsn1Error {
    Asn1(Asn1Error),
    // 沒有任何一列認得這把金鑰或這個演算法
    UnknownPublicKey,
    // 需要公鑰的地方給了私鑰
    NotPublicKey,
    // 公鑰的編碼不是它的演算法要求的
    InvalidPublicKey,
}

impl fmt::Display for AlgoAsn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn1(_) => f.write_str("ASN.1 failure"),
            Self::UnknownPublicKey => f.write_str("unknown public key"),
            Self::NotPublicKey => f.write_str("a private key where a public key is needed"),
            Self::InvalidPublicKey => f.write_str("invalid public key encoding"),
        }
    }
}

impl Error for AlgoAsn1Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Asn1(error) => Some(error),
            Self::UnknownPublicKey | Self::NotPublicKey | Self::InvalidPublicKey => None,
        }
    }
}

impl From<Asn1Error> for AlgoAsn1Error {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}
