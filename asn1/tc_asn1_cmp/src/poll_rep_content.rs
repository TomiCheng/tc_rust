//! RFC 4210 §5.3.22 `PollRepContent`, the body of a polling response.
//!
//! ```text
//! PollRepContent ::= SEQUENCE OF SEQUENCE {
//!     certReqId  INTEGER,
//!     checkAfter INTEGER,
//!     reason     PKIFreeText OPTIONAL }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::PollRep;

/// One answer per request polled.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PollRepContent {
    responses: Asn1SequenceOf<PollRep>,
}

impl PollRepContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<PollRep>) -> Self {
        Self {
            responses: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn responses(&self) -> &[PollRep] {
        self.responses.elements()
    }
}

impl DecodeContent for PollRepContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let responses = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { responses })
    }
}

impl DecodeInner for PollRepContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, responses) = Asn1SequenceOf::<PollRep>::decode_inner(buff, context)?;
        Ok((len, Self { responses }))
    }
}

impl EncodeContent for PollRepContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.responses.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.responses.encode_content(rules, out)
    }
}

impl Decode for PollRepContent {}

impl Tagged for PollRepContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PollRepContent {}

impl Encode for PollRepContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
