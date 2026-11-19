use tc_asn1::{Asn1Oid, DecodingContext, DecodingOptions};
use tc_asn1_cms::signed::{CmsAttribute, SignerIdentifier, SignerInfo};
use tc_asn1_x500::{Attribute, AttributeValue};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_x509::cert::X509Certificate;

use crate::CmsError;
use crate::der::convert;

// BC 的 SignerInformation：一個簽署者，連同所屬 SignedData 的 eContentType。副署
// （countersignature）的簽署者另外記著它副署的簽章值，那就是它簽的內容
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerInformation {
    info: SignerInfo,
    content_type: Asn1Oid,
    countersigned: Option<Vec<u8>>,
}

impl SignerInformation {
    pub(crate) fn new(info: SignerInfo, content_type: Asn1Oid) -> Self {
        Self {
            info,
            content_type,
            countersigned: None,
        }
    }

    // BC 的 GetCounterSignatures：unsigned attributes 裡每個 countersignature 屬性的每個值。
    // 副署的副署也從它們各自的 counter_signatures 取得
    pub fn counter_signatures(&self) -> Result<Vec<SignerInformation>, CmsError> {
        let mut signers = Vec::new();
        let counter = CmsAttribute::COUNTERSIGNATURE.oid();
        for attribute in self.info.unsigned_attrs().unwrap_or_default() {
            if *attribute.attribute_type() != counter {
                continue;
            }
            for value in attribute.values() {
                let AttributeValue::Other(value) = value else {
                    return Err(CmsError::InvalidAttribute("countersignature"));
                };
                signers.push(Self {
                    info: convert(value)?,
                    content_type: self.content_type.clone(),
                    countersigned: Some(self.signature().to_vec()),
                });
            }
        }
        Ok(signers)
    }

    pub fn is_counter_signature(&self) -> bool {
        self.countersigned.is_some()
    }

    // 副署簽的內容：被副署的簽章值
    pub(crate) fn countersigned(&self) -> Option<&[u8]> {
        self.countersigned.as_deref()
    }

    pub fn signer_info(&self) -> &SignerInfo {
        &self.info
    }

    pub fn content_type(&self) -> &Asn1Oid {
        &self.content_type
    }

    pub fn sid(&self) -> &SignerIdentifier {
        self.info.sid()
    }

    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        self.info.digest_algorithm()
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        self.info.signature_algorithm()
    }

    pub fn signed_attributes(&self) -> Option<&[Attribute]> {
        self.info.signed_attrs()
    }

    pub fn unsigned_attributes(&self) -> Option<&[Attribute]> {
        self.info.unsigned_attrs()
    }

    pub fn signature(&self) -> &[u8] {
        self.info.signature().as_bytes()
    }

    // 憑證是不是這個簽署者的，同 BC SignerID.Match：比對簽發者與序號，或 subjectKeyIdentifier
    pub fn is_signer(&self, certificate: &X509Certificate) -> bool {
        match self.sid() {
            SignerIdentifier::IssuerAndSerialNumber(id) => {
                id.serial_number() == certificate.serial_number()
                    && id.issuer().equivalent(certificate.issuer())
            }
            SignerIdentifier::SubjectKeyIdentifier(id) => {
                let mut context = DecodingContext::new(DecodingOptions::default());
                certificate
                    .extensions()
                    .and_then(|extensions| {
                        extensions
                            .get_subject_key_identifier(&mut context)
                            .ok()
                            .flatten()
                    })
                    .is_some_and(|ski| ski.key_identifier() == id.key_identifier())
            }
        }
    }
}
