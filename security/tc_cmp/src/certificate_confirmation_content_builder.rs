use tc_algo::digest::DigestProvider;
use tc_asn1::{Asn1Integer, Asn1OctetString};
use tc_asn1_cmp::{CertConfirmContent, CertStatus, CmpCertificate};
use tc_asn1_x509::alg::AlgorithmIdentifier;

use crate::{CertificateConfirmationContent, CmpError, certificate_status::certificate_hash};

pub struct CertificateConfirmationContentBuilder<'a> {
    digests: &'a dyn DigestProvider,
    statuses: Vec<CertStatus>,
}

impl<'a> CertificateConfirmationContentBuilder<'a> {
    pub fn new(digests: &'a dyn DigestProvider) -> Self {
        Self {
            digests,
            statuses: Vec::new(),
        }
    }

    /// Includes hashAlg for CMP version 3.
    pub fn add_accepted_certificate(
        &mut self,
        certificate: &CmpCertificate,
        request_id: Asn1Integer,
        digest: AlgorithmIdentifier,
    ) -> Result<&mut Self, CmpError> {
        let hash = certificate_hash(certificate, &digest, self.digests)?;
        self.statuses
            .push(CertStatus::new(Asn1OctetString::new(&hash), request_id).with_hash_alg(digest));
        Ok(self)
    }

    /// The supplied digest must be the one implied by the certificate signature.
    pub fn add_accepted_certificate_with_implicit_digest(
        &mut self,
        certificate: &CmpCertificate,
        request_id: Asn1Integer,
        digest: &AlgorithmIdentifier,
    ) -> Result<&mut Self, CmpError> {
        let hash = certificate_hash(certificate, digest, self.digests)?;
        self.statuses
            .push(CertStatus::new(Asn1OctetString::new(&hash), request_id));
        Ok(self)
    }

    pub fn build(self) -> CertificateConfirmationContent {
        CertConfirmContent::new(self.statuses).into()
    }
}
