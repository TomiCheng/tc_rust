use tc_asn1::{Asn1BitString, Asn1GeneralizedTime, Asn1Integer, Asn1OctetString};
use tc_asn1_cmp::{
    CmpCertificate, InfoTypeAndValue, PkiBody, PkiFreeText, PkiHeader, PkiMessage, crmf::CrmfId,
};
use tc_asn1_x509::{alg::AlgorithmIdentifier, cert::Version, name::GeneralName};
use tc_crmf::{CertificateReqMessages, PkMac, PkMacBuilder};
use tc_x509::{cert::X509Certificate, operator::signer::SignatureFactory};

use crate::protected_pki_message::protected_bytes;
use crate::{CertificateConfirmationContent, CmpError, ProtectedPkiMessage};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateRequestType {
    Initialization,
    Certification,
    KeyUpdate,
    KeyRecovery,
    CrossCertification,
}

pub struct ProtectedPkiMessageBuilder {
    header: PkiHeader,
    body: Option<PkiBody>,
    general_info: Vec<InfoTypeAndValue>,
    extra_certs: Vec<CmpCertificate>,
}

impl ProtectedPkiMessageBuilder {
    /// Starts a CMP version 2 message, as Bouncy Castle does by default.
    pub fn new(sender: GeneralName, recipient: GeneralName) -> Self {
        Self::with_version(2.into(), sender, recipient)
    }

    pub fn with_version(version: Asn1Integer, sender: GeneralName, recipient: GeneralName) -> Self {
        Self {
            header: PkiHeader::new(version, sender, recipient),
            body: None,
            general_info: Vec::new(),
            extra_certs: Vec::new(),
        }
    }

    pub fn with_message_time(mut self, time: Asn1GeneralizedTime) -> Self {
        self.header = self.header.with_message_time(time);
        self
    }

    pub fn with_transaction_id(mut self, id: &[u8]) -> Self {
        self.header = self.header.with_transaction_id(Asn1OctetString::new(id));
        self
    }

    pub fn with_sender_kid(mut self, id: &[u8]) -> Self {
        self.header = self.header.with_sender_kid(Asn1OctetString::new(id));
        self
    }

    pub fn with_recip_kid(mut self, id: &[u8]) -> Self {
        self.header = self.header.with_recip_kid(Asn1OctetString::new(id));
        self
    }

    pub fn with_sender_nonce(mut self, nonce: &[u8]) -> Self {
        self.header = self.header.with_sender_nonce(Asn1OctetString::new(nonce));
        self
    }

    pub fn with_recip_nonce(mut self, nonce: &[u8]) -> Self {
        self.header = self.header.with_recip_nonce(Asn1OctetString::new(nonce));
        self
    }

    pub fn with_free_text(mut self, text: PkiFreeText) -> Self {
        self.header = self.header.with_free_text(text);
        self
    }

    pub fn add_general_info(mut self, info: InfoTypeAndValue) -> Self {
        self.general_info.push(info);
        self
    }

    pub fn with_body(mut self, body: PkiBody) -> Self {
        self.body = Some(body);
        self
    }

    pub fn with_certificate_requests(
        self,
        kind: CertificateRequestType,
        requests: &CertificateReqMessages,
    ) -> Self {
        let requests = requests.to_asn1().clone();
        self.with_body(match kind {
            CertificateRequestType::Initialization => PkiBody::Ir(requests),
            CertificateRequestType::Certification => PkiBody::Cr(requests),
            CertificateRequestType::KeyUpdate => PkiBody::Kur(requests),
            CertificateRequestType::KeyRecovery => PkiBody::Krr(requests),
            CertificateRequestType::CrossCertification => PkiBody::Ccr(requests),
        })
    }

    pub fn with_certificate_confirmation(
        self,
        confirmation: &CertificateConfirmationContent,
    ) -> Self {
        self.with_body(PkiBody::CertConf(confirmation.to_asn1().clone()))
    }

    pub fn add_certificate(self, certificate: &X509Certificate) -> Result<Self, CmpError> {
        self.add_cmp_certificate(CmpCertificate::X509v3PkCert(
            certificate.certificate().clone(),
        ))
    }

    pub fn add_cmp_certificate(mut self, certificate: CmpCertificate) -> Result<Self, CmpError> {
        if matches!(&certificate, CmpCertificate::X509v3PkCert(cert) if cert.tbs().version() != Version::V3)
        {
            return Err(CmpError::Invalid(
                "CMPCertificate requires an X.509 v3 certificate",
            ));
        }
        self.extra_certs.push(certificate);
        Ok(self)
    }

    pub fn build(self, signer: &dyn SignatureFactory) -> Result<ProtectedPkiMessage, CmpError> {
        if *signer.algorithm().algorithm() == CrmfId::PASSWORD_BASED_MAC.oid() {
            return Err(CmpError::Invalid(
                "a signature factory cannot produce passwordBasedMac",
            ));
        }
        self.protect(signer.algorithm(), |bytes| {
            let mut calculator = signer.create_calculator()?;
            calculator.write_all(bytes)?;
            Ok(calculator.result().collect()?)
        })
    }

    pub fn build_with_mac(self, mac: &PkMac<'_>) -> Result<ProtectedPkiMessage, CmpError> {
        self.protect(mac.algorithm(), |bytes| Ok(mac.calculate(bytes)?))
    }

    pub fn build_with_password(
        self,
        builder: &PkMacBuilder<'_>,
        password: &str,
    ) -> Result<ProtectedPkiMessage, CmpError> {
        self.build_with_mac(&builder.build(password)?)
    }

    fn protect(
        self,
        algorithm: &AlgorithmIdentifier,
        calculate: impl FnOnce(&[u8]) -> Result<Vec<u8>, CmpError>,
    ) -> Result<ProtectedPkiMessage, CmpError> {
        let body = self
            .body
            .ok_or(CmpError::Invalid("missing CMP message body"))?;
        if matches!(&body, PkiBody::CertConf(content) if content.statuses().iter().any(|status| status.hash_alg().is_some()))
            && self.header.pvno() != &3.into()
        {
            return Err(CmpError::Invalid("certConf hashAlg requires CMP version 3"));
        }
        let mut header = self.header.with_protection_alg(algorithm.clone());
        if !self.general_info.is_empty() {
            header = header.with_general_info(self.general_info);
        }
        let protection = calculate(&protected_bytes(&header, &body)?)?;
        let mut message =
            PkiMessage::new(header, body).with_protection(Asn1BitString::from_bytes(&protection));
        if !self.extra_certs.is_empty() {
            message = message.with_extra_certs(self.extra_certs);
        }
        message.try_into()
    }
}
