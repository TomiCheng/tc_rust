//! RFC 4210 §5.3.22 `PollReqContent`, the body of a polling request.
//!
//! ```text
//! PollReqContent ::= SEQUENCE OF SEQUENCE {
//!     certReqId INTEGER }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::PollReq;

/// The requests to ask about.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PollReqContent {
    requests: Asn1SequenceOf<PollReq>,
}

impl PollReqContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<PollReq>) -> Self {
        Self {
            requests: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn requests(&self) -> &[PollReq] {
        self.requests.elements()
    }
}

impl DecodeContent for PollReqContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let requests = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { requests })
    }
}

impl DecodeInner for PollReqContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, requests) = Asn1SequenceOf::<PollReq>::decode_inner(buff, context)?;
        Ok((len, Self { requests }))
    }
}

impl EncodeContent for PollReqContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.requests.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.requests.encode_content(rules, out)
    }
}

impl Decode for PollReqContent {}

impl Tagged for PollReqContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PollReqContent {}

impl Encode for PollReqContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
