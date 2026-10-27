//! RFC 5544 `Evidence`, what proves when time-stamped data existed.
//!
//! ```text
//! Evidence ::= CHOICE {
//!     tstEvidence    [0] TimeStampTokenEvidence,   -- see RFC 3161
//!     ersEvidence    [1] EvidenceRecord,           -- see RFC 4998
//!     otherEvidence  [2] OtherEvidence }
//! ```
//!
//! The module uses IMPLICIT tags. Evidence records (RFC 4998) and other
//! evidence are kept as the octets they were read with.

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Ref, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Implicit,
};

use crate::tsd::TimeStampTokenEvidence;

/// The evidence of time-stamped data.
///
/// A CHOICE has no tag of its own, so this type does not implement `Tagged`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Evidence {
    /// `[0]`, RFC 3161 time-stamp tokens.
    Tst(TimeStampTokenEvidence),
    /// `[1]`, an RFC 4998 evidence record, kept whole with its tag.
    Ers(Asn1Any),
    /// `[2]`, other evidence, kept whole with its tag.
    Other(Asn1Any),
}

impl From<TimeStampTokenEvidence> for Evidence {
    /// Variable time: branches only on the encoding structure.
    fn from(value: TimeStampTokenEvidence) -> Self {
        Self::Tst(value)
    }
}

impl DecodeInner for Evidence {
    /// The identifier picks the alternative; any other is `UnexpectedTag`.
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?;
        let value = match element.tag() {
            [0xa0] => Self::Tst(TimeStampTokenEvidence::decode_content(
                element.value(),
                context,
            )?),
            [0xa1] => Self::Ers(element.decode_as(context)?),
            [0xa2] => Self::Other(element.decode_as(context)?),
            _ => return Err(Asn1Error::UnexpectedTag),
        };
        Ok((element.total_len(), value))
    }
}

impl Decode for Evidence {}

impl EncodeContent for Evidence {
    /// The contents under the alternative's identifier.
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Tst(inner) => inner.content_len(rules),
            Self::Ers(inner) | Self::Other(inner) => inner.content_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Tst(inner) => inner.encode_content(rules, out),
            Self::Ers(inner) | Self::Other(inner) => inner.encode_content(rules, out),
        }
    }
}

impl EncodeTagged for Evidence {}

impl Encode for Evidence {
    /// The kept alternatives are written back as read.
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        match self {
            Self::Tst(inner) => Implicit::new(&[0xa0], inner).encoded_len(rules),
            Self::Ers(inner) | Self::Other(inner) => inner.encoded_len(rules),
        }
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        match self {
            Self::Tst(inner) => Implicit::new(&[0xa0], inner).encode(rules, out),
            Self::Ers(inner) | Self::Other(inner) => inner.encode(rules, out),
        }
    }
}
