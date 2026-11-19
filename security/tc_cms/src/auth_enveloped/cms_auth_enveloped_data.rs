use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{AuthEnvelopedData, ContentInfo, ContentType};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::der::{convert, decode_all};
use crate::enveloped::RecipientInformation;

// AuthEnvelopedData：以 AEAD 加密並驗證的內容，與能解開它的收件人
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsAuthEnvelopedData {
    data: AuthEnvelopedData,
}

impl CmsAuthEnvelopedData {
    pub fn new(data: AuthEnvelopedData) -> Self {
        Self { data }
    }

    // ContentInfo 包著的 AuthEnvelopedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        let info: ContentInfo = decode_all(der)?;
        if ContentType::AUTH_ENVELOPED_DATA != *info.content_type() {
            return Err(CmsError::UnexpectedContentType);
        }
        let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
        Ok(Self::new(decode_all(content.raw())?))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info = ContentInfo::new(ContentType::AUTH_ENVELOPED_DATA.oid())
            .with_content(convert(&self.data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn auth_enveloped_data(&self) -> &AuthEnvelopedData {
        &self.data
    }

    pub fn content_type(&self) -> &Asn1Oid {
        self.data.auth_encrypted_content_info().content_type()
    }

    pub fn content_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        self.data
            .auth_encrypted_content_info()
            .content_encryption_algorithm()
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
