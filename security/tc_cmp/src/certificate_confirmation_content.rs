use tc_asn1_cmp::{CertConfirmContent, PkiBody};

use crate::{CertificateStatus, CmpError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateConfirmationContent {
    content: CertConfirmContent,
}

impl From<CertConfirmContent> for CertificateConfirmationContent {
    fn from(content: CertConfirmContent) -> Self {
        Self { content }
    }
}

impl CertificateConfirmationContent {
    pub fn from_pki_body(body: &PkiBody) -> Result<Self, CmpError> {
        match body {
            PkiBody::CertConf(content) => Ok(content.clone().into()),
            _ => Err(CmpError::Invalid("expected a CMP certificate confirmation")),
        }
    }

    pub fn status_messages(&self) -> impl Iterator<Item = CertificateStatus<'_>> {
        self.content.statuses().iter().map(CertificateStatus::from)
    }

    pub fn to_asn1(&self) -> &CertConfirmContent {
        &self.content
    }

    pub fn into_asn1(self) -> CertConfirmContent {
        self.content
    }
}
