use tc_asn1::{Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{ContentInfo, ContentType, EnvelopedData};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::CmsError;
use crate::der::{convert, decode_all};
use crate::enveloped::RecipientInformation;

// BC 的 CmsEnvelopedData：加密的內容與能解開它的收件人
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsEnvelopedData {
    enveloped_data: EnvelopedData,
}

impl CmsEnvelopedData {
    pub fn new(enveloped_data: EnvelopedData) -> Self {
        Self { enveloped_data }
    }

    // ContentInfo 包著的 EnvelopedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        let info: ContentInfo = decode_all(der)?;
        if ContentType::ENVELOPED_DATA != *info.content_type() {
            return Err(CmsError::UnexpectedContentType);
        }
        let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
        Ok(Self::new(decode_all(content.raw())?))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info = ContentInfo::new(ContentType::ENVELOPED_DATA.oid())
            .with_content(convert(&self.enveloped_data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn enveloped_data(&self) -> &EnvelopedData {
        &self.enveloped_data
    }

    pub fn content_type(&self) -> &Asn1Oid {
        self.enveloped_data.encrypted_content_info().content_type()
    }

    pub fn content_encryption_algorithm(&self) -> &AlgorithmIdentifier {
        self.enveloped_data
            .encrypted_content_info()
            .content_encryption_algorithm()
    }

    pub fn recipient_infos(&self) -> Vec<RecipientInformation> {
        self.enveloped_data
            .recipient_infos()
            .iter()
            .map(|info| RecipientInformation::new(info.clone()))
            .collect()
    }
}
