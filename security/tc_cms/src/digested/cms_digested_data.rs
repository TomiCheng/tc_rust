use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{ContentInfo, ContentType, DigestedData};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::der::{convert, decode_all, octets};

// BC 的 CmsDigestedData：內容與它的摘要
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsDigestedData {
    data: DigestedData,
}

impl CmsDigestedData {
    pub fn new(data: DigestedData) -> Self {
        Self { data }
    }

    // ContentInfo 包著的 DigestedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        let info: ContentInfo = decode_all(der)?;
        if ContentType::DIGESTED_DATA != *info.content_type() {
            return Err(CmsError::UnexpectedContentType);
        }
        let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
        Ok(Self::new(decode_all(content.raw())?))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info =
            ContentInfo::new(ContentType::DIGESTED_DATA.oid()).with_content(convert(&self.data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn digested_data(&self) -> &DigestedData {
        &self.data
    }

    pub fn content_type(&self) -> &Asn1Oid {
        self.data.encap_content_info().content_type()
    }

    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        self.data.digest_algorithm()
    }

    // 封裝的內容，BC 的 GetDigestedContent；沒封裝時是 None
    pub fn content(&self) -> Result<Option<Vec<u8>>, CmsError> {
        match self.data.encap_content_info().content() {
            Some(content) => Ok(Some(octets(content)?)),
            None => Ok(None),
        }
    }
}
