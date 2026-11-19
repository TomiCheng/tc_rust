use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{AuthenticatedData, ContentInfo, ContentType};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::der::{convert, decode_all, octets};
use crate::enveloped::RecipientInformation;

// BC 的 CmsAuthenticatedData：以 MAC 保護的內容，與能取回 MAC 金鑰的收件人。內容沒有加密
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsAuthenticatedData {
    data: AuthenticatedData,
}

impl CmsAuthenticatedData {
    pub fn new(data: AuthenticatedData) -> Self {
        Self { data }
    }

    // ContentInfo 包著的 AuthenticatedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        let info: ContentInfo = decode_all(der)?;
        if ContentType::AUTHENTICATED_DATA != *info.content_type() {
            return Err(CmsError::UnexpectedContentType);
        }
        let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
        Ok(Self::new(decode_all(content.raw())?))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info = ContentInfo::new(ContentType::AUTHENTICATED_DATA.oid())
            .with_content(convert(&self.data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn authenticated_data(&self) -> &AuthenticatedData {
        &self.data
    }

    pub fn content_type(&self) -> &Asn1Oid {
        self.data.encap_content_info().content_type()
    }

    // 封裝的內容；沒封裝時是 None
    pub fn content(&self) -> Result<Option<Vec<u8>>, CmsError> {
        match self.data.encap_content_info().content() {
            Some(content) => Ok(Some(octets(content)?)),
            None => Ok(None),
        }
    }

    pub fn mac_algorithm(&self) -> &AlgorithmIdentifier {
        self.data.mac_algorithm()
    }

    pub fn mac(&self) -> &[u8] {
        self.data.mac().as_bytes()
    }

    pub fn auth_attributes(&self) -> Option<&[Attribute]> {
        self.data.auth_attrs()
    }

    pub fn unauth_attributes(&self) -> Option<&[Attribute]> {
        self.data.unauth_attrs()
    }

    pub fn recipient_infos(&self) -> Vec<RecipientInformation> {
        self.data
            .recipient_infos()
            .iter()
            .map(|info| RecipientInformation::new(info.clone()))
            .collect()
    }
}
