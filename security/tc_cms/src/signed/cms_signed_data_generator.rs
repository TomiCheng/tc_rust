use tc_asn1::Asn1Oid;
use tc_asn1_cms::content::ContentType;
use tc_x509::cert::X509Certificate;

use crate::signed::SignerInfoGenerator;

// BC 的 CmsSignedDataGenerator：簽署者與附帶的憑證。內容型別預設是 id-data
pub struct CmsSignedDataGenerator {
    pub(crate) signers: Vec<SignerInfoGenerator>,
    pub(crate) certificates: Vec<X509Certificate>,
    pub(crate) content_type: Asn1Oid,
}

impl Default for CmsSignedDataGenerator {
    fn default() -> Self {
        Self {
            signers: Vec::new(),
            certificates: Vec::new(),
            content_type: ContentType::DATA.oid(),
        }
    }
}

impl CmsSignedDataGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_signer(&mut self, signer: SignerInfoGenerator) {
        self.signers.push(signer);
    }

    pub fn add_certificate(&mut self, certificate: X509Certificate) {
        self.certificates.push(certificate);
    }

    pub fn add_certificates(&mut self, certificates: impl IntoIterator<Item = X509Certificate>) {
        self.certificates.extend(certificates);
    }

    pub fn set_content_type(&mut self, content_type: Asn1Oid) {
        self.content_type = content_type;
    }
}
