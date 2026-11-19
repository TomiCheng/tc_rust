use tc_asn1::Asn1Oid;
use tc_asn1_cms::content::ContentType;
use tc_asn1_x500::Attribute;

use crate::enveloped::RecipientInfoGenerator;

// BC 的 CmsAuthenticatedDataGenerator：收件人，以及可選的摘要。沒有摘要時 MAC 直接算在內容上，
// 同 BC C#；有摘要時加上 contentType、messageDigest 與另外給的 authenticated attributes，MAC
// 算在它們的 DER 上，同 RFC 5652 §9.2 與 BC Java
pub struct CmsAuthenticatedDataGenerator {
    pub(crate) recipients: Vec<Box<dyn RecipientInfoGenerator>>,
    pub(crate) content_type: Asn1Oid,
    pub(crate) digest: Option<Asn1Oid>,
    pub(crate) auth_attributes: Vec<Attribute>,
    pub(crate) unauth_attributes: Vec<Attribute>,
}

impl Default for CmsAuthenticatedDataGenerator {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            content_type: ContentType::DATA.oid(),
            digest: None,
            auth_attributes: Vec::new(),
            unauth_attributes: Vec::new(),
        }
    }
}

impl CmsAuthenticatedDataGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_recipient(&mut self, recipient: impl RecipientInfoGenerator + 'static) {
        self.recipients.push(Box::new(recipient));
    }

    pub fn set_content_type(&mut self, content_type: Asn1Oid) {
        self.content_type = content_type;
    }

    // 內容的摘要演算法，如 SHA-256 的 OID；設了就有 authenticated attributes
    pub fn set_digest_algorithm(&mut self, digest: Asn1Oid) {
        self.digest = Some(digest);
    }

    // 有摘要時才寫出
    pub fn add_auth_attribute(&mut self, attribute: Attribute) {
        self.auth_attributes.push(attribute);
    }

    pub fn add_unauth_attribute(&mut self, attribute: Attribute) {
        self.unauth_attributes.push(attribute);
    }
}
