use tc_asn1::{DecodingContext, DecodingOptions};
use tc_asn1_cms::recipient::{KeyAgreeRecipientIdentifier, RecipientIdentifier, RecipientInfo};
use tc_asn1_cms::signed::IssuerAndSerialNumber;
use tc_x509::cert::X509Certificate;

// BC 的 RecipientInformation：一個收件人，四種都解得開
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

    // 憑證是不是這個收件人的，同 BC RecipientID.Match：KeyTrans 與 KeyAgree 依簽發者與序號或
    // subjectKeyIdentifier 比對；KEK 與 Password 不靠憑證識別
    pub fn is_recipient(&self, certificate: &X509Certificate) -> bool {
        match &self.info {
            RecipientInfo::KeyTrans(info) => match info.rid() {
                RecipientIdentifier::IssuerAndSerialNumber(id) => issued_as(id, certificate),
                RecipientIdentifier::SubjectKeyIdentifier(id) => {
                    has_key_identifier(id.key_identifier(), certificate)
                }
            },
            RecipientInfo::KeyAgree(info) => info
                .recipient_encrypted_keys()
                .iter()
                .any(|key| is_key_agree_recipient(key.rid(), certificate)),
            _ => false,
        }
    }
}

pub(crate) fn is_key_agree_recipient(
    rid: &KeyAgreeRecipientIdentifier,
    certificate: &X509Certificate,
) -> bool {
    match rid {
        KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(id) => issued_as(id, certificate),
        KeyAgreeRecipientIdentifier::RKeyId(id) => {
            has_key_identifier(id.subject_key_identifier().key_identifier(), certificate)
        }
    }
}

fn issued_as(id: &IssuerAndSerialNumber, certificate: &X509Certificate) -> bool {
    id.serial_number() == certificate.serial_number()
        && id.issuer().equivalent(certificate.issuer())
}

fn has_key_identifier(key_identifier: &[u8], certificate: &X509Certificate) -> bool {
    let mut context = DecodingContext::new(DecodingOptions::default());
    certificate
        .extensions()
        .and_then(|extensions| {
            extensions
                .get_subject_key_identifier(&mut context)
                .ok()
                .flatten()
        })
        .is_some_and(|ski| ski.key_identifier() == key_identifier)
}
