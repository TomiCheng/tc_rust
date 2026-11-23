use tc_algo::Params;
use tc_asn1::Asn1Integer;
use tc_asn1_cmp::{RevDetails, crmf::CertTemplate};
use tc_asn1_x500::Name;
use tc_asn1_x509::{cert::SubjectPublicKeyInfo, ext::Extensions};
use tc_x509::X509Operator;

use crate::{CmpError, RevocationDetails};

#[derive(Default)]
pub struct RevocationDetailsBuilder {
    template: CertTemplate,
    crl_entry_details: Option<Extensions>,
}

impl RevocationDetailsBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_issuer(&mut self, issuer: Name) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_issuer(issuer);
        self
    }

    pub fn set_serial_number(&mut self, serial: Asn1Integer) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_serial_number(serial);
        self
    }

    pub fn set_subject(&mut self, subject: Name) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_subject(subject);
        self
    }

    pub fn set_subject_public_key_info(&mut self, spki: SubjectPublicKeyInfo) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_public_key(spki);
        self
    }

    pub fn set_public_key(
        &mut self,
        x509: &dyn X509Operator,
        key: &dyn Params,
    ) -> Result<&mut Self, CmpError> {
        Ok(self.set_subject_public_key_info(x509.spki().encode(key)?))
    }

    pub fn set_crl_entry_details(&mut self, extensions: Extensions) -> &mut Self {
        self.crl_entry_details = Some(extensions);
        self
    }

    pub fn build(self) -> RevocationDetails {
        let details = RevDetails::new(self.template);
        match self.crl_entry_details {
            Some(extensions) => details.with_crl_entry_details(extensions),
            None => details,
        }
        .into()
    }
}
