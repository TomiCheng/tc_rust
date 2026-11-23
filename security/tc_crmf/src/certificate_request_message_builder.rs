use tc_algo::Params;
use tc_asn1::{Asn1Integer, Asn1Oid, Encode, EncodingOptions};
use tc_asn1_cmp::crmf::{
    AttributeTypeAndValue, CertReqMsg, CertRequest, CertTemplate, Controls, OptionalValidity,
    PkMacValue, PopoPrivKey, ProofOfPossession, SubsequentMessage,
};
use tc_asn1_x500::Name;
use tc_asn1_x509::{
    cert::{SubjectPublicKeyInfo, Time},
    ext::{Extension, Extensions},
    name::GeneralName,
};
use tc_x509::{X509Operator, operator::signer::SignatureFactory};

use crate::{
    CertificateRequestMessage, Control, CrmfError, PkMacBuilder, ProofOfPossessionSigningKeyBuilder,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubsequentMessageType {
    KeyEncipherment,
    KeyAgreement,
}

enum Pop<'a> {
    Signing(&'a dyn SignatureFactory),
    Subsequent(SubsequentMessageType, SubsequentMessage),
    AgreeMac(PkMacValue),
    RaVerified,
}

pub struct CertificateRequestMessageBuilder<'a> {
    id: Asn1Integer,
    template: CertTemplate,
    extensions: Vec<Extension>,
    controls: Vec<AttributeTypeAndValue>,
    reg_info: Option<Vec<AttributeTypeAndValue>>,
    pop: Option<Pop<'a>>,
    sender: Option<GeneralName>,
    pk_mac: Option<(&'a PkMacBuilder<'a>, &'a str)>,
}

impl<'a> CertificateRequestMessageBuilder<'a> {
    pub fn new(id: Asn1Integer) -> Self {
        Self {
            id,
            template: CertTemplate::new(),
            extensions: Vec::new(),
            controls: Vec::new(),
            reg_info: None,
            pop: None,
            sender: None,
            pk_mac: None,
        }
    }

    pub fn set_reg_info(&mut self, info: Vec<AttributeTypeAndValue>) -> &mut Self {
        self.reg_info = Some(info);
        self
    }

    pub fn set_public_key(
        &mut self,
        x509: &dyn X509Operator,
        key: &dyn Params,
    ) -> Result<&mut Self, CrmfError> {
        Ok(self.set_subject_public_key_info(x509.spki().encode(key)?))
    }

    pub fn set_subject_public_key_info(&mut self, key: SubjectPublicKeyInfo) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_public_key(key);
        self
    }

    pub fn set_issuer(&mut self, issuer: Name) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_issuer(issuer);
        self
    }

    pub fn set_subject(&mut self, subject: Name) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_subject(subject);
        self
    }

    pub fn set_serial_number(&mut self, serial: Asn1Integer) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_serial_number(serial);
        self
    }

    pub fn set_validity(&mut self, validity: OptionalValidity) -> &mut Self {
        self.template = std::mem::take(&mut self.template).with_validity(validity);
        self
    }

    pub fn set_validity_bounds(
        &mut self,
        not_before: Option<Time>,
        not_after: Option<Time>,
    ) -> &mut Self {
        let mut validity = OptionalValidity::new();
        if let Some(time) = not_before {
            validity = validity.with_not_before(time);
        }
        if let Some(time) = not_after {
            validity = validity.with_not_after(time);
        }
        self.set_validity(validity)
    }

    pub fn add_extension(
        &mut self,
        oid: Asn1Oid,
        critical: bool,
        value: &(impl Encode + ?Sized),
    ) -> Result<&mut Self, CrmfError> {
        self.add_extension_der(oid, critical, &value.encode_to_vec(&EncodingOptions::DER)?)
    }

    pub fn add_extension_der(
        &mut self,
        oid: Asn1Oid,
        critical: bool,
        value: &[u8],
    ) -> Result<&mut Self, CrmfError> {
        if self
            .extensions
            .iter()
            .any(|extension| extension.extn_id() == &oid)
        {
            return Err(CrmfError::Invalid(
                "duplicate certificate template extension",
            ));
        }
        self.extensions.push(Extension::new(oid, critical, value));
        Ok(self)
    }

    pub fn add_control(&mut self, control: Control) -> Result<&mut Self, CrmfError> {
        Ok(self.add_raw_control(control.to_asn1()?))
    }

    pub fn add_raw_control(&mut self, control: AttributeTypeAndValue) -> &mut Self {
        self.controls.push(control);
        self
    }

    pub fn set_proof_of_possession_signing_key_signer(
        &mut self,
        signer: &'a dyn SignatureFactory,
    ) -> Result<&mut Self, CrmfError> {
        self.set_pop(Pop::Signing(signer))
    }

    pub fn set_proof_of_possession_subsequent_message(
        &mut self,
        message: SubsequentMessage,
    ) -> Result<&mut Self, CrmfError> {
        self.set_proof_of_possession_subsequent_message_with_type(
            SubsequentMessageType::KeyEncipherment,
            message,
        )
    }

    pub fn set_proof_of_possession_subsequent_message_with_type(
        &mut self,
        kind: SubsequentMessageType,
        message: SubsequentMessage,
    ) -> Result<&mut Self, CrmfError> {
        self.set_pop(Pop::Subsequent(kind, message))
    }

    pub fn set_proof_of_possession_agree_mac(
        &mut self,
        value: PkMacValue,
    ) -> Result<&mut Self, CrmfError> {
        self.set_pop(Pop::AgreeMac(value))
    }

    pub fn set_proof_of_possession_ra_verified(&mut self) -> Result<&mut Self, CrmfError> {
        self.set_pop(Pop::RaVerified)
    }

    pub fn set_auth_info_sender(&mut self, sender: GeneralName) -> &mut Self {
        self.sender = Some(sender);
        self
    }

    pub fn set_auth_info_sender_name(&mut self, sender: Name) -> &mut Self {
        self.set_auth_info_sender(GeneralName::DirectoryName(sender))
    }

    pub fn set_auth_info_pk_mac_builder(
        &mut self,
        builder: &'a PkMacBuilder<'a>,
        password: &'a str,
    ) -> &mut Self {
        self.pk_mac = Some((builder, password));
        self
    }

    pub fn build(&self) -> Result<CertificateRequestMessage, CrmfError> {
        let mut template = self.template.clone();
        if !self.extensions.is_empty() {
            template = template.with_extensions(Extensions::new(self.extensions.clone())?);
        }
        let mut request = CertRequest::new(self.id.clone(), template);
        if !self.controls.is_empty() {
            request = request.with_controls(Controls::new(self.controls.clone())?);
        }

        let pop = match &self.pop {
            Some(Pop::Signing(signer)) => {
                ProofOfPossession::Signature(self.signing_pop(&request, *signer)?)
            }
            Some(Pop::Subsequent(kind, message)) => {
                let private_key = PopoPrivKey::SubsequentMessage(*message);
                match kind {
                    SubsequentMessageType::KeyEncipherment => {
                        ProofOfPossession::KeyEncipherment(private_key)
                    }
                    SubsequentMessageType::KeyAgreement => {
                        ProofOfPossession::KeyAgreement(private_key)
                    }
                }
            }
            Some(Pop::AgreeMac(value)) => {
                ProofOfPossession::KeyAgreement(PopoPrivKey::AgreeMac(value.clone()))
            }
            Some(Pop::RaVerified) | None => ProofOfPossession::RaVerified,
        };
        let mut message = CertReqMsg::new(request).with_popo(pop);
        if let Some(info) = &self.reg_info {
            message = message.with_reg_info(info.clone());
        }
        Ok(message.into())
    }

    fn set_pop(&mut self, pop: Pop<'a>) -> Result<&mut Self, CrmfError> {
        if self.pop.is_some() {
            return Err(CrmfError::Invalid(
                "only one proof of possession is allowed",
            ));
        }
        self.pop = Some(pop);
        Ok(self)
    }

    fn signing_pop(
        &self,
        request: &CertRequest,
        signer: &dyn SignatureFactory,
    ) -> Result<tc_asn1_cmp::crmf::PopoSigningKey, CrmfError> {
        let template = request.cert_template();
        let public_key = template.public_key().ok_or(CrmfError::Invalid(
            "signing proof of possession requires a public key in the certificate template",
        ))?;
        if template.subject().is_some() {
            return ProofOfPossessionSigningKeyBuilder::from_cert_request(request).build(signer);
        }
        let mut builder = ProofOfPossessionSigningKeyBuilder::from_public_key(public_key);
        if let Some(sender) = &self.sender {
            builder.set_sender(sender.clone());
        } else if let Some((mac, password)) = self.pk_mac {
            builder.set_public_key_mac(mac, password)?;
        } else {
            return Err(CrmfError::Invalid(
                "signing proof of possession without a subject requires a sender or PKMAC",
            ));
        }
        builder.build(signer)
    }
}
