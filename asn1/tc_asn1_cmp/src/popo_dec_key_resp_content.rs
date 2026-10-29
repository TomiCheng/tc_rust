//! RFC 4210 §5.2.8 `POPODecKeyRespContent`, the body of a POP response.
//!
//! ```text
//! POPODecKeyRespContent ::= SEQUENCE OF INTEGER
//! ```

use alloc::vec::Vec;

use tc_asn1::Asn1Integer;
use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The decrypted random integers, one per challenge.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PopoDecKeyRespContent {
    responses: Asn1SequenceOf<Asn1Integer>,
}

impl PopoDecKeyRespContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<Asn1Integer>) -> Self {
        Self {
            responses: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn responses(&self) -> &[Asn1Integer] {
        self.responses.elements()
    }
}

impl DecodeContent for PopoDecKeyRespContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let responses = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { responses })
    }
}

impl DecodeInner for PopoDecKeyRespContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, responses) = Asn1SequenceOf::<Asn1Integer>::decode_inner(buff, context)?;
        Ok((len, Self { responses }))
    }
}

impl EncodeContent for PopoDecKeyRespContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.responses.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.responses.encode_content(rules, out)
    }
}

impl Decode for PopoDecKeyRespContent {}

impl Tagged for PopoDecKeyRespContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PopoDecKeyRespContent {}

impl Encode for PopoDecKeyRespContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
