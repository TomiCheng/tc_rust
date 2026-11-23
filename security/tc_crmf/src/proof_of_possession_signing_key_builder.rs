use tc_asn1::{Asn1BitString, Encode, EncodingOptions};
use tc_asn1_cmp::crmf::{AuthInfo, CertRequest, PkMacValue, PopoSigningKey, PopoSigningKeyInput};
use tc_asn1_x509::{cert::SubjectPublicKeyInfo, name::GeneralName};
use tc_x509::operator::signer::SignatureFactory;

use crate::{CrmfError, PkMacBuilder, PkMacValueGenerator};

enum SigningInput<'a> {
    Request(&'a CertRequest),
    PublicKey(&'a SubjectPublicKeyInfo),
}

pub struct ProofOfPossessionSigningKeyBuilder<'a> {
    input: SigningInput<'a>,
    sender: Option<GeneralName>,
    public_key_mac: Option<PkMacValue>,
}

impl<'a> ProofOfPossessionSigningKeyBuilder<'a> {
    pub fn from_cert_request(request: &'a CertRequest) -> Self {
        Self {
            input: SigningInput::Request(request),
            sender: None,
            public_key_mac: None,
        }
    }

    pub fn from_public_key(public_key: &'a SubjectPublicKeyInfo) -> Self {
        Self {
            input: SigningInput::PublicKey(public_key),
            sender: None,
            public_key_mac: None,
        }
    }

    pub fn set_sender(&mut self, sender: GeneralName) -> &mut Self {
        self.sender = Some(sender);
        self
    }

    pub fn set_public_key_mac(
        &mut self,
        builder: &PkMacBuilder<'_>,
        password: &str,
    ) -> Result<&mut Self, CrmfError> {
        let SigningInput::PublicKey(public_key) = self.input else {
            return Err(CrmfError::Invalid(
                "publicKeyMAC requires a public-key signing input",
            ));
        };
        self.public_key_mac = Some(PkMacValueGenerator::generate(
            builder, password, public_key,
        )?);
        Ok(self)
    }

    pub fn build(&self, factory: &dyn SignatureFactory) -> Result<PopoSigningKey, CrmfError> {
        if self.sender.is_some() && self.public_key_mac.is_some() {
            return Err(CrmfError::Invalid(
                "sender and publicKeyMAC cannot both be set",
            ));
        }
        let mut calculator = factory.create_calculator()?;
        let input = match self.input {
            SigningInput::Request(request) => {
                calculator.write_all(&request.encode_to_vec(&EncodingOptions::DER)?)?;
                None
            }
            SigningInput::PublicKey(public_key) => {
                let auth = if let Some(sender) = &self.sender {
                    AuthInfo::Sender(sender.clone())
                } else if let Some(mac) = &self.public_key_mac {
                    AuthInfo::PublicKeyMac(mac.clone())
                } else {
                    return Err(CrmfError::Invalid(
                        "signing input requires a sender or PKMAC",
                    ));
                };
                let input = PopoSigningKeyInput::new(auth, public_key.clone());
                calculator.write_all(&input.encode_to_vec(&EncodingOptions::DER)?)?;
                Some(input)
            }
        };
        let signature = Asn1BitString::from_bytes(&calculator.result().collect()?);
        let pop = PopoSigningKey::new(factory.algorithm().clone(), signature);
        Ok(match input {
            Some(input) => pop.with_poposk_input(input),
            None => pop,
        })
    }
}
