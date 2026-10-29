//! The reduction polynomial of a DSTU 4145 binary field.
//!
//! ```text
//! CHOICE {
//!     Trinomial,
//!     Pentanomial }
//! Trinomial ::= INTEGER
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, tag,
};

use crate::Dstu4145Pentanomial;

/// A trinomial `x^m + x^k + 1` by `k`, or a pentanomial.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Dstu4145Exponents {
    /// The exponent `k` of a trinomial.
    Trinomial(Asn1Integer),
    /// The exponents of a pentanomial.
    Pentanomial(Dstu4145Pentanomial),
}

impl DecodeInner for Dstu4145Exponents {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            tag::INTEGER => Self::Trinomial(element.decode_as(context)?),
            tag::SEQUENCE => Self::Pentanomial(element.decode_as(context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for Dstu4145Exponents {}

impl EncodeContent for Dstu4145Exponents {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Trinomial(inner) => inner.content_len(rules),
            Self::Pentanomial(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Trinomial(inner) => inner.encode_content(rules, out),
            Self::Pentanomial(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for Dstu4145Exponents {}

impl Encode for Dstu4145Exponents {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Trinomial(inner) => inner.encoded_len(rules),
            Self::Pentanomial(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Trinomial(inner) => inner.encode(rules, out),
            Self::Pentanomial(inner) => inner.encode(rules, out),
        }
    }
}
