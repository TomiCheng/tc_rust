//! RFC 5280 §4.1.2 `TBSCertificate`, the signed part of a certificate.
//!
//! ```text
//! TBSCertificate ::= SEQUENCE {
//!     version              [0] EXPLICIT Version DEFAULT v1,
//!     serialNumber         CertificateSerialNumber,
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     validity             Validity,
//!     subject              Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     issuerUniqueID       [1] IMPLICIT UniqueIdentifier OPTIONAL,  -- v2 or v3
//!     subjectUniqueID      [2] IMPLICIT UniqueIdentifier OPTIONAL,  -- v2 or v3
//!     extensions           [3] EXPLICIT Extensions OPTIONAL         -- v3
//! }
//!
//! Version ::= INTEGER { v1(0), v2(1), v3(2) }
//! CertificateSerialNumber ::= INTEGER
//! UniqueIdentifier ::= BIT STRING
//! ```
//!
//! The version is implied by what is present: extensions need v3, unique
//! identifiers need v2 or v3. The serial number is meant to be positive and
//! at most 20 octets, but RFC 5280 asks decoders to accept what CAs have
//! issued, so it is kept as is. The unique identifiers are obsolete; they
//! are read for old certificates and MUST NOT be generated.
//!
//! Signature verification needs the octets exactly as received, not a
//! re-encoding; the enclosing `Certificate` keeps those.

use core::fmt;

use tc_asn1::{
    Asn1BitString, Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Implicit, Tagged, tag,
};
use tc_asn1_x500::Name;

use crate::{AlgorithmIdentifier, Extensions, SubjectPublicKeyInfo, Validity};

/// The certificate version, `Version ::= INTEGER { v1(0), v2(1), v3(2) }`.
/// Note the offset: v1 is encoded as 0.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

impl Version {
    /// The INTEGER value: 0, 1 or 2.
    pub fn number(self) -> u8 {
        self as u8
    }

    /// From the INTEGER value; anything but 0, 1 or 2 is `MalformedValue`.
    pub fn from_number(number: u8) -> Result<Self, Asn1Error> {
        match number {
            0 => Ok(Self::V1),
            1 => Ok(Self::V2),
            2 => Ok(Self::V3),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

/// `v1`, `v2` or `v3`.
impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.number() + 1)
    }
}

/// The fields a CA signs.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TbsCertificate {
    version: Version,
    serial_number: Asn1Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: Option<Asn1BitString>,
    subject_unique_id: Option<Asn1BitString>,
    extensions: Option<Extensions>,
}

impl TbsCertificate {
    /// The mandatory fields; the optional ones are added with the `with_`
    /// methods, which check them against the version.
    pub fn new(
        version: Version,
        serial_number: Asn1Integer,
        signature: AlgorithmIdentifier,
        issuer: Name,
        validity: Validity,
        subject: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
    ) -> Self {
        Self {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        }
    }

    /// The unique identifiers, which RFC 5280 allows only from v2 on;
    /// `MalformedValue` for a v1 certificate.
    pub fn with_unique_ids(
        mut self,
        issuer_unique_id: Option<Asn1BitString>,
        subject_unique_id: Option<Asn1BitString>,
    ) -> Result<Self, Asn1Error> {
        if self.version == Version::V1
            && (issuer_unique_id.is_some() || subject_unique_id.is_some())
        {
            return Err(Asn1Error::MalformedValue);
        }
        self.issuer_unique_id = issuer_unique_id;
        self.subject_unique_id = subject_unique_id;
        Ok(self)
    }

    /// The extensions, which RFC 5280 allows only in v3; `MalformedValue`
    /// otherwise.
    pub fn with_extensions(mut self, extensions: Extensions) -> Result<Self, Asn1Error> {
        if self.version != Version::V3 {
            return Err(Asn1Error::MalformedValue);
        }
        self.extensions = Some(extensions);
        Ok(self)
    }

    pub fn version(&self) -> Version {
        self.version
    }

    /// As issued; may be negative or longer than 20 octets in old or
    /// non-conforming certificates.
    pub fn serial_number(&self) -> &Asn1Integer {
        &self.serial_number
    }

    /// The signature algorithm, which must match the outer certificate's.
    pub fn signature(&self) -> &AlgorithmIdentifier {
        &self.signature
    }

    pub fn issuer(&self) -> &Name {
        &self.issuer
    }

    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    pub fn subject(&self) -> &Name {
        &self.subject
    }

    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfo {
        &self.subject_public_key_info
    }

    pub fn issuer_unique_id(&self) -> Option<&Asn1BitString> {
        self.issuer_unique_id.as_ref()
    }

    pub fn subject_unique_id(&self) -> Option<&Asn1BitString> {
        self.subject_unique_id.as_ref()
    }

    pub fn extensions(&self) -> Option<&Extensions> {
        self.extensions.as_ref()
    }
}

impl DecodeInner for TbsCertificate {
    /// The optional fields are recognized by their context tags. A version
    /// other than 0, 1 or 2, unique identifiers in v1 or extensions outside
    /// v3 are `MalformedValue`; a written v1 is `NotDer` under DER.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(tag::SEQUENCE)?;
        let mut children = element.children(context)?;
        let version: Asn1Integer = children.get_explicit_default([0xA0], Asn1Integer::from(0))?;
        let serial_number: Asn1Integer = children.get()?;
        let signature: AlgorithmIdentifier = children.get()?;
        let issuer: Name = children.get()?;
        let validity: Validity = children.get()?;
        let subject: Name = children.get()?;
        let subject_public_key_info: SubjectPublicKeyInfo = children.get()?;
        let issuer_unique_id = children.get_implicit_opt::<Asn1BitString>([0x81])?;
        let subject_unique_id = children.get_implicit_opt::<Asn1BitString>([0x82])?;
        let extensions = children.get_explicit_opt::<Extensions>([0xA3])?;
        children.end()?;

        let version =
            Version::from_number(u8::try_from(&version).map_err(|_| Asn1Error::MalformedValue)?)?;
        let tbs = Self::new(
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
        )
        .with_unique_ids(issuer_unique_id, subject_unique_id)?;
        let tbs = match extensions {
            Some(extensions) => tbs.with_extensions(extensions)?,
            None => tbs,
        };
        Ok((element.total_len(), tbs))
    }
}

impl Decode for TbsCertificate {}

impl Tagged for TbsCertificate {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeContent for TbsCertificate {
    /// The fields' TLVs back to back: the version only from v2 on, v1 being
    /// the DEFAULT, and the optional fields only when present.
    /// Variable time: branches only on the structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        let mut len = 0;
        if self.version != Version::V1 {
            let version = Asn1Integer::from(self.version.number());
            len += Explicit::new(&[0xA0], &version).encoded_len(rules);
        }
        len += self.serial_number.encoded_len(rules);
        len += self.signature.encoded_len(rules);
        len += self.issuer.encoded_len(rules);
        len += self.validity.encoded_len(rules);
        len += self.subject.encoded_len(rules);
        len += self.subject_public_key_info.encoded_len(rules);
        if let Some(id) = &self.issuer_unique_id {
            len += Implicit::new(&[0x81], id).encoded_len(rules);
        }
        if let Some(id) = &self.subject_unique_id {
            len += Implicit::new(&[0x82], id).encoded_len(rules);
        }
        if let Some(extensions) = &self.extensions {
            len += Explicit::new(&[0xA3], extensions).encoded_len(rules);
        }
        len
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if self.version != Version::V1 {
            let version = Asn1Integer::from(self.version.number());
            at += Explicit::new(&[0xA0], &version).encode(rules, &mut out[at..])?;
        }
        at += self.serial_number.encode(rules, &mut out[at..])?;
        at += self.signature.encode(rules, &mut out[at..])?;
        at += self.issuer.encode(rules, &mut out[at..])?;
        at += self.validity.encode(rules, &mut out[at..])?;
        at += self.subject.encode(rules, &mut out[at..])?;
        at += self.subject_public_key_info.encode(rules, &mut out[at..])?;
        if let Some(id) = &self.issuer_unique_id {
            at += Implicit::new(&[0x81], id).encode(rules, &mut out[at..])?;
        }
        if let Some(id) = &self.subject_unique_id {
            at += Implicit::new(&[0x82], id).encode(rules, &mut out[at..])?;
        }
        if let Some(extensions) = &self.extensions {
            at += Explicit::new(&[0xA3], extensions).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl EncodeTagged for TbsCertificate {}

impl Encode for TbsCertificate {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
