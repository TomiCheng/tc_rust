use tc_asn1::{Encode, EncodingOptions};
use tc_asn1_cmp::{CmpCertificate, PkiBody, PkiHeader, PkiMessage, ProtectedPart, crmf::CrmfId};
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_crmf::PkMacBuilder;
use tc_x509::operator::verifier::{VerifierFactory, VerifierFactoryProvider};

use crate::{CmpError, GeneralPkiMessage};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedPkiMessage {
    message: PkiMessage,
}

impl TryFrom<PkiMessage> for ProtectedPkiMessage {
    type Error = CmpError;

    fn try_from(message: PkiMessage) -> Result<Self, Self::Error> {
        let protection = message
            .protection()
            .ok_or(CmpError::Invalid("missing PKIProtection"))?;
        if message.header().protection_alg().is_none() {
            return Err(CmpError::Invalid("missing protectionAlg"));
        }
        if protection.unused_bits() != 0 || protection.as_bytes().is_empty() {
            return Err(CmpError::Invalid("PKIProtection must contain whole octets"));
        }
        Ok(Self { message })
    }
}

impl TryFrom<GeneralPkiMessage> for ProtectedPkiMessage {
    type Error = CmpError;

    fn try_from(message: GeneralPkiMessage) -> Result<Self, Self::Error> {
        message.into_asn1().try_into()
    }
}

impl ProtectedPkiMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self, CmpError> {
        GeneralPkiMessage::decode(bytes)?.try_into()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CmpError> {
        Ok(self.message.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn header(&self) -> &PkiHeader {
        self.message.header()
    }

    pub fn body(&self) -> &PkiBody {
        self.message.body()
    }

    pub fn to_asn1(&self) -> &PkiMessage {
        &self.message
    }

    pub fn into_asn1(self) -> PkiMessage {
        self.message
    }

    pub fn protection_algorithm(&self) -> &AlgorithmIdentifier {
        self.header()
            .protection_alg()
            .expect("checked at construction")
    }

    pub fn has_password_based_mac_protection(&self) -> bool {
        *self.protection_algorithm().algorithm() == CrmfId::PASSWORD_BASED_MAC.oid()
    }

    /// Extra certificates are untrusted and are outside the signed or MACed part.
    pub fn extra_certificates(&self) -> &[CmpCertificate] {
        self.message.extra_certs().unwrap_or_default()
    }

    pub fn verify_signature(
        &self,
        provider: &dyn VerifierFactoryProvider,
    ) -> Result<bool, CmpError> {
        self.verify_signature_with_factory(
            &*provider.create_verifier_factory(self.protection_algorithm())?,
        )
    }

    pub fn verify_signature_with_factory(
        &self,
        factory: &dyn VerifierFactory,
    ) -> Result<bool, CmpError> {
        if self.has_password_based_mac_protection()
            || factory.algorithm() != self.protection_algorithm()
        {
            return Err(CmpError::Invalid(
                "signature verifier does not match protectionAlg",
            ));
        }
        let mut calculator = factory.create_calculator()?;
        calculator.write_all(&self.protected_bytes()?)?;
        Ok(calculator.result().is_verified(self.protection())?)
    }

    pub fn verify_password_based_mac(
        &self,
        builder: &PkMacBuilder<'_>,
        password: &str,
    ) -> Result<bool, CmpError> {
        let mac = builder.get(self.protection_algorithm(), password)?;
        Ok(mac.verify(&self.protected_bytes()?, self.protection())?)
    }

    fn protected_bytes(&self) -> Result<Vec<u8>, CmpError> {
        protected_bytes(self.header(), self.body())
    }

    fn protection(&self) -> &[u8] {
        self.message
            .protection()
            .expect("checked at construction")
            .as_bytes()
    }
}

pub(crate) fn protected_bytes(header: &PkiHeader, body: &PkiBody) -> Result<Vec<u8>, CmpError> {
    Ok(ProtectedPart::new(header.clone(), body.clone()).encode_to_vec(&EncodingOptions::DER)?)
}
