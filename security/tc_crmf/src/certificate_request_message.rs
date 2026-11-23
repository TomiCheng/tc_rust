use tc_asn1::{Asn1Any, Asn1Integer, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cmp::crmf::{
    AttributeTypeAndValue, AuthInfo, CertReqMsg, CertTemplate, PopoSigningKey, ProofOfPossession,
};
use tc_x509::operator::verifier::VerifierFactoryProvider;

use crate::{Control, CrmfError, PkMacBuilder, PkMacValueVerifier, der};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofOfPossessionType {
    RaVerified,
    SigningKey,
    KeyEncipherment,
    KeyAgreement,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequestMessage {
    message: CertReqMsg,
}

impl From<CertReqMsg> for CertificateRequestMessage {
    fn from(message: CertReqMsg) -> Self {
        Self { message }
    }
}

impl CertificateRequestMessage {
    pub fn decode(bytes: &[u8]) -> Result<Self, CrmfError> {
        Ok(Self::from(der::decode::<CertReqMsg>(bytes)?))
    }

    pub fn encode(&self) -> Result<Vec<u8>, CrmfError> {
        Ok(self.message.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn to_asn1(&self) -> &CertReqMsg {
        &self.message
    }

    pub fn cert_req_id(&self) -> &Asn1Integer {
        self.message.cert_req().cert_req_id()
    }

    pub fn cert_template(&self) -> &CertTemplate {
        self.message.cert_req().cert_template()
    }

    pub fn controls(&self) -> &[AttributeTypeAndValue] {
        self.message
            .cert_req()
            .controls()
            .map_or(&[], |controls| controls.controls())
    }

    pub fn has_controls(&self) -> bool {
        self.message.cert_req().controls().is_some()
    }

    pub fn find_control(&self, oid: &Asn1Oid) -> Option<&AttributeTypeAndValue> {
        self.controls()
            .iter()
            .find(|control| control.attribute_type() == oid)
    }

    pub fn has_control(&self, oid: &Asn1Oid) -> bool {
        self.find_control(oid).is_some()
    }

    pub fn control_value(&self, oid: &Asn1Oid) -> Option<&Asn1Any> {
        self.find_control(oid).map(AttributeTypeAndValue::value)
    }

    pub fn control(&self, oid: &Asn1Oid) -> Result<Option<Control>, CrmfError> {
        match self.find_control(oid) {
            Some(value) => Control::decode(value),
            None => Ok(None),
        }
    }

    pub fn reg_info(&self) -> Option<&[AttributeTypeAndValue]> {
        self.message.reg_info()
    }

    pub fn has_proof_of_possession(&self) -> bool {
        self.message.popo().is_some()
    }

    pub fn proof_of_possession_type(&self) -> Option<ProofOfPossessionType> {
        Some(match self.message.popo()? {
            ProofOfPossession::RaVerified => ProofOfPossessionType::RaVerified,
            ProofOfPossession::Signature(_) => ProofOfPossessionType::SigningKey,
            ProofOfPossession::KeyEncipherment(_) => ProofOfPossessionType::KeyEncipherment,
            ProofOfPossession::KeyAgreement(_) => ProofOfPossessionType::KeyAgreement,
        })
    }

    pub fn has_signing_key_pop_with_pk_mac(&self) -> bool {
        let Some(ProofOfPossession::Signature(pop)) = self.message.popo() else {
            return false;
        };
        pop.poposk_input()
            .is_some_and(|input| matches!(input.auth_info(), AuthInfo::PublicKeyMac(_)))
    }

    pub fn is_valid_signing_key_pop(
        &self,
        provider: &dyn VerifierFactoryProvider,
    ) -> Result<bool, CrmfError> {
        let pop = self.signing_key_pop()?;
        if self.has_signing_key_pop_with_pk_mac() {
            return Err(CrmfError::Invalid("verification requires a password check"));
        }
        self.verify_signature(provider, pop)
    }

    pub fn is_valid_signing_key_pop_with_mac(
        &self,
        provider: &dyn VerifierFactoryProvider,
        builder: &PkMacBuilder<'_>,
        password: &str,
    ) -> Result<bool, CrmfError> {
        let pop = self.signing_key_pop()?;
        let Some(AuthInfo::PublicKeyMac(value)) = pop.poposk_input().map(|input| input.auth_info())
        else {
            return Err(CrmfError::Invalid(
                "no PKMAC present in proof of possession",
            ));
        };
        let key = self
            .cert_template()
            .public_key()
            .ok_or(CrmfError::Invalid("certificate template has no public key"))?;
        Ok(
            PkMacValueVerifier::new(builder).is_valid(value, password, key)?
                && self.verify_signature(provider, pop)?,
        )
    }

    fn signing_key_pop(&self) -> Result<&PopoSigningKey, CrmfError> {
        let Some(ProofOfPossession::Signature(pop)) = self.message.popo() else {
            return Err(CrmfError::Invalid(
                "expected signing-key proof of possession",
            ));
        };
        Ok(pop)
    }

    fn verify_signature(
        &self,
        provider: &dyn VerifierFactoryProvider,
        pop: &PopoSigningKey,
    ) -> Result<bool, CrmfError> {
        if pop.signature().unused_bits() != 0 {
            return Ok(false);
        }
        let signed: &dyn Encode = match pop.poposk_input() {
            Some(input) => {
                if self.cert_template().public_key() != Some(input.public_key()) {
                    return Ok(false);
                }
                input
            }
            None => self.message.cert_req(),
        };
        let factory = provider.create_verifier_factory(pop.algorithm_identifier())?;
        let mut calculator = factory.create_calculator()?;
        calculator.write_all(&signed.encode_to_vec(&EncodingOptions::DER)?)?;
        Ok(calculator
            .result()
            .is_verified(pop.signature().as_bytes())?)
    }
}
