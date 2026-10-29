//! RFC 2986 §4.1 `CertificationRequestInfo`, the signed part of a PKCS #10
//! certification request.
//!
//! ```text
//! CertificationRequestInfo ::= SEQUENCE {
//!     version       INTEGER { v1(0) } (v1,...),
//!     subject       Name,
//!     subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
//!     attributes    [0] Attributes{{ CRIAttributes }} }
//! ```
//!
//! RFC 2986 requires `attributes`, possibly empty; Bouncy Castle also reads it
//! absent, and so does this type.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Asn1SetOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Implicit, Tagged, tag,
};
use tc_asn1_x500::{Attribute, Name};
use tc_asn1_x509::cert::SubjectPublicKeyInfo;

/// The subject, its public key and attributes such as `extensionRequest`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificationRequestInfo {
    version: Option<Asn1Integer>,
    subject: Name,
    subject_pk_info: SubjectPublicKeyInfo,
    attributes: Option<Asn1SetOf<Attribute>>,
}

impl CertificationRequestInfo {
    /// The subject and its public key, without attributes.
    /// Variable time: branches only on the encoding structure.
    pub fn new(subject: Name, subject_pk_info: SubjectPublicKeyInfo) -> Self {
        Self {
            version: None,
            subject,
            subject_pk_info,
            attributes: None,
        }
    }

    /// Sets the attributes; an empty list writes the empty set RFC 2986 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn with_attributes(mut self, attributes: Vec<Attribute>) -> Self {
        self.attributes = Some(Asn1SetOf::new(attributes));
        self
    }

    /// Returns the decoded version, or the one RFC 2986 calls for.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version
            .clone()
            .unwrap_or_else(|| self.derived_version())
    }

    /// Always 0.
    fn derived_version(&self) -> Asn1Integer {
        0.into()
    }

    /// Returns the subject.
    /// Variable time: branches only on the encoding structure.
    pub fn subject(&self) -> &Name {
        &self.subject
    }

    /// Returns the subject public key.
    /// Variable time: branches only on the encoding structure.
    pub fn subject_pk_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_pk_info
    }

    /// Returns the attributes in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn attributes(&self) -> Option<&[Attribute]> {
        self.attributes.as_ref().map(Asn1SetOf::members)
    }
}

impl DecodeContent for CertificationRequestInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version: Asn1Integer = fields.get()?;
        let subject = fields.get()?;
        let subject_pk_info = fields.get()?;
        let attributes = fields.get_implicit_opt([0xa0])?;
        fields.end()?;
        let mut value = Self {
            version: None,
            subject,
            subject_pk_info,
            attributes,
        };
        if version != value.derived_version() {
            value.version = Some(version);
        }
        Ok(value)
    }
}

impl DecodeInner for CertificationRequestInfo {
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

impl EncodeContent for CertificationRequestInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version().encoded_len(rules)
            + self.subject.encoded_len(rules)
            + self.subject_pk_info.encoded_len(rules)
            + self
                .attributes
                .as_ref()
                .map_or(0, |v| Implicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.version().encode(rules, out)?;
        at += self.subject.encode(rules, &mut out[at..])?;
        at += self.subject_pk_info.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.attributes {
            at += Implicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertificationRequestInfo {}

impl Tagged for CertificationRequestInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertificationRequestInfo {}

impl Encode for CertificationRequestInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
