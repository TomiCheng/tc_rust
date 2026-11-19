use std::io::Write;

use tc_asn1::{Asn1BitString, Encode, EncodingOptions};
use tc_asn1_pkcs::{CertificationRequest, CertificationRequestInfo, Pkcs9Attribute};
use tc_asn1_x500::{Attribute, Name};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_asn1_x509::ext::{Extension, Extensions};
use tc_x509::operator::signer::SignatureFactory;

use crate::PkcsError;
use crate::csr::Pkcs10CertificationRequest;
use crate::der::to_object;

// Makes a Pkcs10CertificationRequest, as the constructors of Bouncy Castle's take the subject, the
// public key and the attributes. The extensions go into one extensionRequest attribute of PKCS#9
#[derive(Clone, Debug, Default)]
pub struct Pkcs10CertificationRequestBuilder {
    subject: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
    attributes: Vec<Attribute>,
    extensions: Vec<Extension>,
}

impl Pkcs10CertificationRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_subject(&mut self, subject: Name) {
        self.subject = Some(subject);
    }

    // The subject from a string such as "CN=example,O=Acme"; Asn1 when it does not parse
    pub fn set_subject_by_str(&mut self, subject: &str) -> Result<(), PkcsError> {
        self.subject = Some(subject.parse()?);
        Ok(())
    }

    // As x509.spki().encode(public_key) gives it
    pub fn set_subject_public_key_info(&mut self, subject_public_key_info: SubjectPublicKeyInfo) {
        self.subject_public_key_info = Some(subject_public_key_info);
    }

    pub fn add_attribute(&mut self, attribute: Attribute) {
        self.attributes.push(attribute);
    }

    pub fn add_extension(&mut self, extension: Extension) {
        self.extensions.push(extension);
    }

    // Signed with the private key behind the factory, which is that of the public key set here.
    // MissingField without a subject or a public key
    pub fn generate(
        &self,
        factory: &dyn SignatureFactory,
    ) -> Result<Pkcs10CertificationRequest, PkcsError> {
        let subject = self
            .subject
            .clone()
            .ok_or(PkcsError::MissingField("subject"))?;
        let subject_public_key_info = self
            .subject_public_key_info
            .clone()
            .ok_or(PkcsError::MissingField("subject_public_key_info"))?;
        let mut attributes = self.attributes.clone();
        if !self.extensions.is_empty() {
            let extensions = Extensions::new(self.extensions.clone())?;
            attributes.push(Attribute::new(
                Pkcs9Attribute::EXTENSION_REQUEST.oid(),
                vec![to_object(&extensions)?.into()],
            )?);
        }
        let info = CertificationRequestInfo::new(subject, subject_public_key_info)
            .with_attributes(attributes);
        let der = info.encode_to_vec(&EncodingOptions::DER)?;

        let mut calculator = factory.create_calculator()?;
        calculator
            .write_all(&der)
            .map_err(tc_x509::X509Error::from)?;
        let signature = calculator.result().collect()?;

        Ok(Pkcs10CertificationRequest::new(CertificationRequest::new(
            info,
            factory.algorithm().clone(),
            Asn1BitString::from_bytes(&signature),
        )))
    }
}
