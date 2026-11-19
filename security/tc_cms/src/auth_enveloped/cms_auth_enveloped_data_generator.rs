use tc_asn1::Asn1Oid;
use tc_asn1_cms::content::ContentType;
use tc_asn1_x500::Attribute;

use crate::enveloped::RecipientInfoGenerator;

// BC Java 的 CMSAuthEnvelopedDataGenerator：收件人與 authenticated attributes。內容型別預設是
// id-data；不是時，或另有 authenticated attributes 時，contentType 屬性會加上，同 RFC 5083
pub struct CmsAuthEnvelopedDataGenerator {
    pub(crate) recipients: Vec<Box<dyn RecipientInfoGenerator>>,
    pub(crate) content_type: Asn1Oid,
    pub(crate) auth_attributes: Vec<Attribute>,
    pub(crate) unauth_attributes: Vec<Attribute>,
}

impl Default for CmsAuthEnvelopedDataGenerator {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            content_type: ContentType::DATA.oid(),
            auth_attributes: Vec::new(),
            unauth_attributes: Vec::new(),
        }
    }
}

impl CmsAuthEnvelopedDataGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_recipient(&mut self, recipient: impl RecipientInfoGenerator + 'static) {
        self.recipients.push(Box::new(recipient));
    }

    pub fn set_content_type(&mut self, content_type: Asn1Oid) {
        self.content_type = content_type;
    }

    // 與內容一起驗證的屬性，以它們的 DER 當 AEAD 的 AAD
    pub fn add_auth_attribute(&mut self, attribute: Attribute) {
        self.auth_attributes.push(attribute);
    }

    pub fn add_unauth_attribute(&mut self, attribute: Attribute) {
        self.unauth_attributes.push(attribute);
    }
}
