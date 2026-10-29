//! RFC 4210 §5.3.20 `GenRepContent`, the body of a general response.
//!
//! ```text
//! GenRepContent ::= SEQUENCE OF InfoTypeAndValue
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::InfoTypeAndValue;

/// The information returned.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct GenRepContent {
    items: Asn1SequenceOf<InfoTypeAndValue>,
}

impl GenRepContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<InfoTypeAndValue>) -> Self {
        Self {
            items: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn items(&self) -> &[InfoTypeAndValue] {
        self.items.elements()
    }
}

impl DecodeContent for GenRepContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let items = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { items })
    }
}

impl DecodeInner for GenRepContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, items) = Asn1SequenceOf::<InfoTypeAndValue>::decode_inner(buff, context)?;
        Ok((len, Self { items }))
    }
}

impl EncodeContent for GenRepContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.items.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.items.encode_content(rules, out)
    }
}

impl Decode for GenRepContent {}

impl Tagged for GenRepContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for GenRepContent {}

impl Encode for GenRepContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
