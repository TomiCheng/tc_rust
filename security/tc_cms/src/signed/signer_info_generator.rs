use tc_asn1_cms::signed::{IssuerAndSerialNumber, SignerIdentifier};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::ext::SubjectKeyIdentifier;
use tc_x509::cert::X509Certificate;
use tc_x509::operator::signer::SignatureFactory;

use crate::CmsError;
use crate::algorithms::digest_of;

// BC 的 SignerInfoGenerator：一個簽署者的簽章 factory、識別與屬性。預設有 signed attributes
// （contentType、signingTime、messageDigest、cmsAlgorithmProtect），同 BC 的
// DefaultSignedAttributeTableGenerator；另外加的同型別屬性會取代預設的
pub struct SignerInfoGenerator {
    pub(crate) factory: Box<dyn SignatureFactory>,
    pub(crate) sid: SignerIdentifier,
    pub(crate) digest_algorithm: AlgorithmIdentifier,
    pub(crate) signed_attributes: bool,
    pub(crate) extra_signed: Vec<Attribute>,
    pub(crate) unsigned: Vec<Attribute>,
}

impl SignerInfoGenerator {
    // 以憑證的簽發者與序號識別簽署者；摘要演算法由簽章演算法決定，不認得時是 UnknownAlgorithm
    pub fn new(
        factory: Box<dyn SignatureFactory>,
        certificate: &X509Certificate,
    ) -> Result<Self, CmsError> {
        let digest_algorithm = digest_of(factory.algorithm())?;
        Ok(Self {
            factory,
            sid: IssuerAndSerialNumber::of(certificate.certificate()).into(),
            digest_algorithm,
            signed_attributes: true,
            extra_signed: Vec::new(),
            unsigned: Vec::new(),
        })
    }

    // 改以 subjectKeyIdentifier 識別，SignerInfo 成為 version 3
    pub fn with_subject_key_identifier(mut self, key_identifier: &[u8]) -> Result<Self, CmsError> {
        self.sid = SubjectKeyIdentifier::new(key_identifier.to_vec())?.into();
        Ok(self)
    }

    // 直接簽內容、不帶 signed attributes，同 BC 的 SetDirectSignature(true)
    pub fn without_signed_attributes(mut self) -> Self {
        self.signed_attributes = false;
        self
    }

    pub fn with_signed_attribute(mut self, attribute: Attribute) -> Self {
        self.extra_signed.push(attribute);
        self
    }

    pub fn with_unsigned_attribute(mut self, attribute: Attribute) -> Self {
        self.unsigned.push(attribute);
        self
    }
}
