use tc_asn1::Asn1Oid;
use tc_asn1_cms::content::ContentType;

use crate::enveloped::RecipientInfoGenerator;

// BC 的 CmsEnvelopedDataGenerator：收件人。內容型別預設是 id-data
pub struct CmsEnvelopedDataGenerator {
    pub(crate) recipients: Vec<Box<dyn RecipientInfoGenerator>>,
    pub(crate) content_type: Asn1Oid,
}

impl Default for CmsEnvelopedDataGenerator {
    fn default() -> Self {
        Self {
            recipients: Vec::new(),
            content_type: ContentType::DATA.oid(),
        }
    }
}

impl CmsEnvelopedDataGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_recipient(&mut self, recipient: impl RecipientInfoGenerator + 'static) {
        self.recipients.push(Box::new(recipient));
    }

    pub fn set_content_type(&mut self, content_type: Asn1Oid) {
        self.content_type = content_type;
    }
}
