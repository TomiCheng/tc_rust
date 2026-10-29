//! One entry of RFC 5126 §5.11.3 `SignerAttribute`.
//!
//! ```text
//! CHOICE {
//!     claimedAttributes   [0] ClaimedAttributes,
//!     certifiedAttributes [1] CertifiedAttributes }
//! ClaimedAttributes ::= SEQUENCE OF Attribute
//! CertifiedAttributes ::= AttributeCertificate
//! ```
//!
//! The module uses explicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit,
};
use tc_asn1_x500::Attribute;
use tc_asn1_x509::attr::AttributeCertificate;

/// Attributes the signer claims, or an attribute certificate that certifies them.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
// Keep the attribute certificate inline as part of the public value API, without an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum SignerAttributeEntry {
    /// `[0]`, attributes such as a role, claimed by the signer.
    ClaimedAttributes(Asn1SequenceOf<Attribute>),
    /// `[1]`, attributes certified by an attribute authority.
    CertifiedAttributes(AttributeCertificate),
}

impl SignerAttributeEntry {
    /// Claimed attributes, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn claimed(attributes: Vec<Attribute>) -> Self {
        Self::ClaimedAttributes(Asn1SequenceOf::new(attributes))
    }

    fn tag(&self) -> &'static [u8] {
        match self {
            Self::ClaimedAttributes(_) => &[0xa0],
            Self::CertifiedAttributes(_) => &[0xa1],
        }
    }

    fn inner(&self) -> &dyn Encode {
        match self {
            Self::ClaimedAttributes(inner) => inner,
            Self::CertifiedAttributes(inner) => inner,
        }
    }
}

impl From<AttributeCertificate> for SignerAttributeEntry {
    /// Variable time: branches only on the encoding structure.
    fn from(value: AttributeCertificate) -> Self {
        Self::CertifiedAttributes(value)
    }
}

impl DecodeInner for SignerAttributeEntry {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let tag = element.tag();
        if tag != [0xa0] && tag != [0xa1] {
            return Err(Asn1Error::UnexpectedTag);
        }
        let mut inner = element.children(context)?;
        let value = if tag == [0xa0] {
            Self::ClaimedAttributes(inner.get()?)
        } else {
            Self::CertifiedAttributes(inner.get()?)
        };
        inner.end()?;
        Ok((element.total_len(), value))
    }
}

impl Decode for SignerAttributeEntry {}

impl EncodeContent for SignerAttributeEntry {
    /// The contents under the alternative's identifier: the inner element.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.inner().encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.inner().encode(rules, out)
    }
}

impl EncodeTagged for SignerAttributeEntry {}

impl Encode for SignerAttributeEntry {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        Explicit::new(self.tag(), self.inner()).encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        Explicit::new(self.tag(), self.inner()).encode(rules, out)
    }
}
