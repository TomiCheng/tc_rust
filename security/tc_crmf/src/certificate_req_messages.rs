use tc_asn1_cmp::{PkiBody, crmf::CertReqMessages};

use crate::{CertificateRequestMessage, CrmfError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateReqMessages {
    messages: CertReqMessages,
}

impl From<CertReqMessages> for CertificateReqMessages {
    fn from(messages: CertReqMessages) -> Self {
        Self { messages }
    }
}

impl CertificateReqMessages {
    pub fn from_pki_body(body: &PkiBody) -> Result<Self, CrmfError> {
        let messages = match body {
            PkiBody::Ir(messages)
            | PkiBody::Cr(messages)
            | PkiBody::Kur(messages)
            | PkiBody::Krr(messages)
            | PkiBody::Ccr(messages) => messages,
            _ => {
                return Err(CrmfError::Invalid(
                    "PKIBody does not contain certificate request messages",
                ));
            }
        };
        Ok(messages.clone().into())
    }

    pub fn is_certificate_request_messages(body: &PkiBody) -> bool {
        matches!(
            body,
            PkiBody::Ir(_) | PkiBody::Cr(_) | PkiBody::Kur(_) | PkiBody::Krr(_) | PkiBody::Ccr(_)
        )
    }

    pub fn requests(&self) -> Vec<CertificateRequestMessage> {
        self.messages
            .messages()
            .iter()
            .cloned()
            .map(Into::into)
            .collect()
    }

    pub fn to_asn1(&self) -> &CertReqMessages {
        &self.messages
    }
}
