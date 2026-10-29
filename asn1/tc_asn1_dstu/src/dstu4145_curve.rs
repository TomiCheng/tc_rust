//! The curve of DSTU 4145 parameters.
//!
//! ```text
//! CHOICE {
//!     ecbinary   ECBinary,
//!     namedCurve OBJECT IDENTIFIER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, tag,
};

use crate::Dstu4145EcBinary;

/// A named curve, or an explicit one.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Dstu4145Curve {
    /// A named curve, from `UaId`.
    NamedCurve(Asn1Oid),
    /// An explicit curve.
    EcBinary(Dstu4145EcBinary),
}

impl DecodeInner for Dstu4145Curve {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::OBJECT_IDENTIFIER => Self::NamedCurve(element.decode_as(context)?),
            tag::SEQUENCE => Self::EcBinary(element.decode_as(context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for Dstu4145Curve {}

impl EncodeContent for Dstu4145Curve {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::NamedCurve(inner) => inner.content_len(rules),
            Self::EcBinary(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::NamedCurve(inner) => inner.encode_content(rules, out),
            Self::EcBinary(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for Dstu4145Curve {}

impl Encode for Dstu4145Curve {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::NamedCurve(inner) => inner.encoded_len(rules),
            Self::EcBinary(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::NamedCurve(inner) => inner.encode(rules, out),
            Self::EcBinary(inner) => inner.encode(rules, out),
        }
    }
}
