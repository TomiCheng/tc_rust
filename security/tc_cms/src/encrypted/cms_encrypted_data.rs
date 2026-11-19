use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{ContentInfo, ContentType, EncryptedData};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::der::{convert, decode_all};

// 以對稱金鑰加密的內容
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsEncryptedData {
    data: EncryptedData,
}

impl CmsEncryptedData {
    pub fn new(data: EncryptedData) -> Self {
        Self { data }
    }

    // ContentInfo 包著的 EncryptedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        let info: ContentInfo = decode_all(der)?;
        if ContentType::ENCRYPTED_DATA != *info.content_type() {
            return Err(CmsError::UnexpectedContentType);
        }
        let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
        Ok(Self::new(decode_all(content.raw())?))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info =
            ContentInfo::new(ContentType::ENCRYPTED_DATA.oid()).with_content(convert(&self.data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn encrypted_data(&self) -> &EncryptedData {
        &self.data
    }

    pub fn content_type(&self) -> &Asn1Oid {
        self.data.encrypted_content_info().content_type()
    }

    pub fn content_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        self.data
            .encrypted_content_info()
            .content_encryption_algorithm()
    }

    pub fn unprotected_attributes(&self) -> Option<&[Attribute]> {
        self.data.unprotected_attrs()
    }
}
