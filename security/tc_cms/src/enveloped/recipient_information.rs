use tc_asn1::{DecodingContext, DecodingOptions};
use tc_asn1_cms::recipient::{RecipientIdentifier, RecipientInfo};
use tc_x509::cert::X509Certificate;

// BC 的 RecipientInformation：一個收件人。KeyTrans、KEK 與 Password 解得開
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientInformation {
    info: RecipientInfo,
}

impl RecipientInformation {
    pub(crate) fn new(info: RecipientInfo) -> Self {
        Self { info }
    }

    pub fn recipient_info(&self) -> &RecipientInfo {
        &self.info
    }

    // KEK 收件人的金鑰識別碼，其他種類是 None
    pub fn kek_identifier(&self) -> Option<&[u8]> {
        match &self.info {
            RecipientInfo::Kek(info) => Some(info.kekid().key_identifier().as_bytes()),
            _ => None,
        }
    }

    pub fn is_password(&self) -> bool {
        matches!(self.info, RecipientInfo::Password(_))
    }

    // 憑證是不是這個收件人的，同 BC RecipientID.Match：KeyTrans 依簽發者與序號或
    // subjectKeyIdentifier 比對；其他種類的收件人不靠憑證識別
    pub fn is_recipient(&self, certificate: &X509Certificate) -> bool {
        let RecipientInfo::KeyTrans(info) = &self.info else {
            return false;
        };
        match info.rid() {
            RecipientIdentifier::IssuerAndSerialNumber(id) => {
                id.serial_number() == certificate.serial_number()
                    && id.issuer().equivalent(certificate.issuer())
            }
            RecipientIdentifier::SubjectKeyIdentifier(id) => {
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
