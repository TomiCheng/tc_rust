use tc_asn1::{Asn1OctetString, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cms::content::{CertificateChoices, ContentInfo, ContentType, SignedData};
use tc_x509::cert::X509Certificate;

use crate::CmsError;
use crate::der::{convert, decode_all};
use crate::signed::SignerInformation;

// BC 的 CmsSignedData：一份 SignedData，連同簽署的內容。內容沒封裝（detached）時另外給
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CmsSignedData {
    signed_data: SignedData,
    content: Option<Vec<u8>>,
}

impl CmsSignedData {
    // 內容取自 eContent，沒封裝就沒有
    pub fn new(signed_data: SignedData) -> Result<Self, CmsError> {
        let content = match signed_data.encap_content_info().content() {
            Some(content) => Some(
                decode_all::<Asn1OctetString>(content.raw())?
                    .as_bytes()
                    .to_vec(),
            ),
            None => None,
        };
        Ok(Self {
            signed_data,
            content,
        })
    }

    // 沒封裝的 SignedData 與另外傳來的內容，同 BC 的 CmsSignedData(content, encoding)
    pub fn with_detached_content(signed_data: SignedData, content: Vec<u8>) -> Self {
        Self {
            signed_data,
            content: Some(content),
        }
    }

    // ContentInfo 包著的 SignedData
    pub fn decode(der: &[u8]) -> Result<Self, CmsError> {
        Self::new(signed_data_of(der)?)
    }

    pub fn decode_detached(der: &[u8], content: Vec<u8>) -> Result<Self, CmsError> {
        Ok(Self::with_detached_content(signed_data_of(der)?, content))
    }

    // ContentInfo 包著的 DER
    pub fn encode(&self) -> Result<Vec<u8>, CmsError> {
        let info = ContentInfo::new(ContentType::SIGNED_DATA.oid())
            .with_content(convert(&self.signed_data)?);
        Ok(info.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn signed_data(&self) -> &SignedData {
        &self.signed_data
    }

    pub fn signed_content_type(&self) -> &Asn1Oid {
        self.signed_data.encap_content_info().content_type()
    }

    pub fn signed_content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    // 內容有沒有封裝在 SignedData 裡
    pub fn is_detached(&self) -> bool {
        self.signed_data.encap_content_info().content().is_none()
    }

    pub fn signer_infos(&self) -> Vec<SignerInformation> {
        let content_type = self.signed_content_type();
        self.signed_data
            .signer_infos()
            .iter()
            .map(|info| SignerInformation::new(info.clone(), content_type.clone()))
            .collect()
    }

    // 附帶的 X.509 憑證；其他格式略過
    pub fn certificates(&self) -> Vec<X509Certificate> {
        self.signed_data
            .certificates()
            .unwrap_or_default()
            .iter()
            .filter_map(|choice| match choice {
                CertificateChoices::Certificate(certificate) => {
                    Some(X509Certificate::new(certificate.clone()))
                }
                _ => None,
            })
            .collect()
    }
}

fn signed_data_of(der: &[u8]) -> Result<SignedData, CmsError> {
    let info: ContentInfo = decode_all(der)?;
    if ContentType::SIGNED_DATA != *info.content_type() {
        return Err(CmsError::UnexpectedContentType);
    }
    let content = info.content().ok_or(CmsError::UnexpectedContentType)?;
    decode_all(content.raw())
}
