//! The identifier of RFC 4211 §4.4 `EncKeyWithID`.
//!
//! ```text
//! identifier CHOICE {
//!     string      UTF8String,
//!     generalName GeneralName }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1Utf8String, Decode, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, tag,
};
use tc_asn1_x509::name::GeneralName;

/// A name for the key, as free text or a general name.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum EncKeyWithIdIdentifier {
    /// Free text.
    String(Asn1Utf8String),
    /// A general name.
    GeneralName(GeneralName),
}

impl DecodeInner for EncKeyWithIdIdentifier {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::UTF8_STRING => Self::String(element.decode_as(context)?),
            _ => Self::GeneralName(element.decode_as(context)?),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for EncKeyWithIdIdentifier {}

impl EncodeContent for EncKeyWithIdIdentifier {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::String(inner) => inner.content_len(rules),
            Self::GeneralName(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::String(inner) => inner.encode_content(rules, out),
            Self::GeneralName(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for EncKeyWithIdIdentifier {}

impl Encode for EncKeyWithIdIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::String(inner) => inner.encoded_len(rules),
            Self::GeneralName(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::String(inner) => inner.encode(rules, out),
            Self::GeneralName(inner) => inner.encode(rules, out),
        }
    }
}
