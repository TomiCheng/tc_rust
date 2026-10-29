//! RFC 4211 §5 `CertTemplate`, the fields of the certificate asked for.
//!
//! ```text
//! CertTemplate ::= SEQUENCE {
//!     version      [0] Version               OPTIONAL,
//!     serialNumber [1] INTEGER               OPTIONAL,
//!     signingAlg   [2] AlgorithmIdentifier   OPTIONAL,
//!     issuer       [3] Name                  OPTIONAL,
//!     validity     [4] OptionalValidity      OPTIONAL,
//!     subject      [5] Name                  OPTIONAL,
//!     publicKey    [6] SubjectPublicKeyInfo  OPTIONAL,
//!     issuerUID    [7] UniqueIdentifier      OPTIONAL,
//!     subjectUID   [8] UniqueIdentifier      OPTIONAL,
//!     extensions   [9] Extensions            OPTIONAL }
//! ```
//!
//! The module uses implicit tags; `Name` is a CHOICE, so `issuer` and `subject`
//! are explicit.

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Implicit,
    Tagged, tag,
};
use tc_asn1_x500::Name;
use tc_asn1_x509::alg::AlgorithmIdentifier;
use tc_asn1_x509::cert::SubjectPublicKeyInfo;
use tc_asn1_x509::ext::Extensions;

use crate::crmf::OptionalValidity;

/// Any of the fields of a certificate; the CA fills in the rest.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub struct CertTemplate {
    version: Option<Asn1Integer>,
    serial_number: Option<Asn1Integer>,
    signing_alg: Option<AlgorithmIdentifier>,
    issuer: Option<Name>,
    validity: Option<OptionalValidity>,
    subject: Option<Name>,
    public_key: Option<SubjectPublicKeyInfo>,
    issuer_uid: Option<Asn1BitString>,
    subject_uid: Option<Asn1BitString>,
    extensions: Option<Extensions>,
}

impl CertTemplate {
    /// A template with every field absent.
    /// Variable time: branches only on the encoding structure.
    pub fn new() -> Self {
        Self {
            version: None,
            serial_number: None,
            signing_alg: None,
            issuer: None,
            validity: None,
            subject: None,
            public_key: None,
            issuer_uid: None,
            subject_uid: None,
            extensions: None,
        }
    }

    /// Sets the version.
    /// Variable time: branches only on the encoding structure.
    pub fn with_version(mut self, version: Asn1Integer) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the serial number.
    /// Variable time: branches only on the encoding structure.
    pub fn with_serial_number(mut self, serial_number: Asn1Integer) -> Self {
        self.serial_number = Some(serial_number);
        self
    }

    /// Sets the signing algorithm.
    /// Variable time: branches only on the encoding structure.
    pub fn with_signing_alg(mut self, signing_alg: AlgorithmIdentifier) -> Self {
        self.signing_alg = Some(signing_alg);
        self
    }

    /// Sets the issuer.
    /// Variable time: branches only on the encoding structure.
    pub fn with_issuer(mut self, issuer: Name) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Sets the validity.
    /// Variable time: branches only on the encoding structure.
    pub fn with_validity(mut self, validity: OptionalValidity) -> Self {
        self.validity = Some(validity);
        self
    }

    /// Sets the subject.
    /// Variable time: branches only on the encoding structure.
    pub fn with_subject(mut self, subject: Name) -> Self {
        self.subject = Some(subject);
        self
    }

    /// Sets the public key.
    /// Variable time: branches only on the encoding structure.
    pub fn with_public_key(mut self, public_key: SubjectPublicKeyInfo) -> Self {
        self.public_key = Some(public_key);
        self
    }

    /// Sets the issuer unique identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_issuer_uid(mut self, issuer_uid: Asn1BitString) -> Self {
        self.issuer_uid = Some(issuer_uid);
        self
    }

    /// Sets the subject unique identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn with_subject_uid(mut self, subject_uid: Asn1BitString) -> Self {
        self.subject_uid = Some(subject_uid);
        self
    }

    /// Sets the extensions.
    /// Variable time: branches only on the encoding structure.
    pub fn with_extensions(mut self, extensions: Extensions) -> Self {
        self.extensions = Some(extensions);
        self
    }

    /// Returns the version, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Option<&Asn1Integer> {
        self.version.as_ref()
    }

    /// Returns the serial number, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn serial_number(&self) -> Option<&Asn1Integer> {
        self.serial_number.as_ref()
    }

    /// Returns the signing algorithm, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn signing_alg(&self) -> Option<&AlgorithmIdentifier> {
        self.signing_alg.as_ref()
    }

    /// Returns the issuer, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer(&self) -> Option<&Name> {
        self.issuer.as_ref()
    }

    /// Returns the validity, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn validity(&self) -> Option<&OptionalValidity> {
        self.validity.as_ref()
    }

    /// Returns the subject, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn subject(&self) -> Option<&Name> {
        self.subject.as_ref()
    }

    /// Returns the public key, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn public_key(&self) -> Option<&SubjectPublicKeyInfo> {
        self.public_key.as_ref()
    }

    /// Returns the issuer unique identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn issuer_uid(&self) -> Option<&Asn1BitString> {
        self.issuer_uid.as_ref()
    }

    /// Returns the subject unique identifier, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn subject_uid(&self) -> Option<&Asn1BitString> {
        self.subject_uid.as_ref()
    }

    /// Returns the extensions, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeContent for CertTemplate {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version = fields.get_implicit_opt([0x80])?;
        let serial_number = fields.get_implicit_opt([0x81])?;
        let signing_alg = fields.get_implicit_opt([0xa2])?;
        let issuer = fields.get_explicit_opt::<Name>([0xa3])?;
        let validity = fields.get_implicit_opt([0xa4])?;
        let subject = fields.get_explicit_opt::<Name>([0xa5])?;
        let public_key = fields.get_implicit_opt([0xa6])?;
        let issuer_uid = fields.get_implicit_opt([0x87])?;
        let subject_uid = fields.get_implicit_opt([0x88])?;
        let extensions = fields.get_implicit_opt([0xa9])?;
        fields.end()?;
        let value = Self {
            version,
            serial_number,
            signing_alg,
            issuer,
            validity,
            subject,
            public_key,
            issuer_uid,
            subject_uid,
            extensions,
        };
        Ok(value)
    }
}

impl DecodeInner for CertTemplate {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for CertTemplate {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version
            .as_ref()
            .map_or(0, |v| Implicit::new(&[0x80], v).encoded_len(rules))
            + self
                .serial_number
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x81], v).encoded_len(rules))
            + self
                .signing_alg
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa2], v).encoded_len(rules))
            + self
                .issuer
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa3], v).encoded_len(rules))
            + self
                .validity
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa4], v).encoded_len(rules))
            + self
                .subject
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa5], v).encoded_len(rules))
            + self
                .public_key
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa6], v).encoded_len(rules))
            + self
                .issuer_uid
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x87], v).encoded_len(rules))
            + self
                .subject_uid
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0x88], v).encoded_len(rules))
            + self
                .extensions
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa9], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.version {
            at += Implicit::new(&[0x80], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.serial_number {
            at += Implicit::new(&[0x81], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.signing_alg {
            at += Implicit::new(&[0xa2], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.issuer {
            at += Explicit::new(&[0xa3], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.validity {
            at += Implicit::new(&[0xa4], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.subject {
            at += Explicit::new(&[0xa5], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.public_key {
            at += Implicit::new(&[0xa6], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.issuer_uid {
            at += Implicit::new(&[0x87], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.subject_uid {
            at += Implicit::new(&[0x88], v).encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.extensions {
            at += Implicit::new(&[0xa9], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertTemplate {}

impl Tagged for CertTemplate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertTemplate {}

impl Encode for CertTemplate {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
