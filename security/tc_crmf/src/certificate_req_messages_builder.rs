use tc_asn1_cmp::crmf::{CertReqMessages, CertReqMsg};

use crate::{CertificateReqMessages, CertificateRequestMessage, CrmfError};

#[derive(Default)]
pub struct CertificateReqMessagesBuilder {
    requests: Vec<CertReqMsg>,
}

impl CertificateReqMessagesBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_request(&mut self, request: &CertificateRequestMessage) {
        self.requests.push(request.to_asn1().clone());
    }

    pub fn build(&mut self) -> Result<CertificateReqMessages, CrmfError> {
        Ok(CertReqMessages::new(std::mem::take(&mut self.requests))?.into())
    }
}
