//! RFC 4210 §5.3.9 `RevReqContent`, the body of a revocation request.
//!
//! ```text
//! RevReqContent ::= SEQUENCE OF RevDetails
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::RevDetails;

/// The certificates to revoke.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct RevReqContent {
    details: Asn1SequenceOf<RevDetails>,
}

impl RevReqContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<RevDetails>) -> Self {
        Self {
            details: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn details(&self) -> &[RevDetails] {
        self.details.elements()
    }
}

impl DecodeContent for RevReqContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let details = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { details })
    }
}

impl DecodeInner for RevReqContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, details) = Asn1SequenceOf::<RevDetails>::decode_inner(buff, context)?;
        Ok((len, Self { details }))
    }
}

impl EncodeContent for RevReqContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.details.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.details.encode_content(rules, out)
    }
}

impl Decode for RevReqContent {}

impl Tagged for RevReqContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for RevReqContent {}

impl Encode for RevReqContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
