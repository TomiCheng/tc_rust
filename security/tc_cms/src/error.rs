use core::error::Error;
use core::fmt;

use tc_algo::AlgoError;
use tc_asn1::Asn1Error;
use tc_x509::X509Error;

// 這個 crate 的錯誤，包住底層 crate 的錯誤
#[derive(Debug)]
#[non_exhaustive]
pub enum CmsError {
    Algo(AlgoError),
    Asn1(Asn1Error),
    X509(X509Error),
    // 簽章驗不過
    InvalidSignature,
    // 有 signed attributes 時，少了必要的屬性，或屬性不是單一值
    InvalidAttribute(&'static str),
    // messageDigest 與內容的摘要不符
    MessageDigestMismatch,
    // contentType 屬性與 eContentType 不符
    ContentTypeMismatch,
    // cmsAlgorithmProtect 與 SignerInfo 的演算法不符
    AlgorithmProtectionMismatch,
    // 不認得的摘要或簽章演算法
    UnknownAlgorithm,
    // 內容沒有封裝，驗證要另外給
    MissingContent,
    // ContentInfo 不是 SignedData
    NotSignedData,
    // 簽章時間不在憑證的有效期間內
    CertificateNotValid,
}

impl fmt::Display for CmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Algo(error) => write!(f, "{error}"),
            Self::Asn1(error) => write!(f, "{error}"),
            Self::X509(error) => write!(f, "{error}"),
            Self::InvalidSignature => f.write_str("the signature does not verify"),
            Self::InvalidAttribute(name) => write!(f, "invalid {name} attribute"),
            Self::MessageDigestMismatch => {
                f.write_str("message-digest attribute value does not match calculated value")
            }
            Self::ContentTypeMismatch => {
                f.write_str("content-type attribute value does not match eContentType")
            }
            Self::AlgorithmProtectionMismatch => {
                f.write_str("CMS algorithm protection check failed")
            }
            Self::UnknownAlgorithm => f.write_str("unknown digest or signature algorithm"),
            Self::MissingContent => f.write_str("the content is not encapsulated"),
            Self::NotSignedData => f.write_str("the content info is not signed data"),
            Self::CertificateNotValid => {
                f.write_str("the certificate is not valid at the signing time")
            }
        }
    }
}

impl Error for CmsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Algo(error) => Some(error),
            Self::Asn1(error) => Some(error),
            Self::X509(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AlgoError> for CmsError {
    fn from(error: AlgoError) -> Self {
        Self::Algo(error)
    }
}

impl From<Asn1Error> for CmsError {
    fn from(error: Asn1Error) -> Self {
        Self::Asn1(error)
    }
}

impl From<X509Error> for CmsError {
    fn from(error: X509Error) -> Self {
        Self::X509(error)
    }
}
