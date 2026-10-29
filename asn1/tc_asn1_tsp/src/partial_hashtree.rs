//! RFC 4998 §4.2 `PartialHashtree`, one level of a reduced hash tree.
//!
//! ```text
//! PartialHashtree ::= SEQUENCE OF OCTET STRING
//! ```

use alloc::vec::Vec;

use tc_asn1::Asn1OctetString;
use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The hash values on one level of the tree.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PartialHashtree {
    values: Asn1SequenceOf<Asn1OctetString>,
}

impl PartialHashtree {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<Asn1OctetString>) -> Self {
        Self {
            values: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn values(&self) -> &[Asn1OctetString] {
        self.values.elements()
    }
}

impl DecodeContent for PartialHashtree {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let values = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { values })
    }
}

impl DecodeInner for PartialHashtree {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, values) = Asn1SequenceOf::<Asn1OctetString>::decode_inner(buff, context)?;
        Ok((len, Self { values }))
    }
}

impl EncodeContent for PartialHashtree {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.values.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.values.encode_content(rules, out)
    }
}

impl Decode for PartialHashtree {}

impl Tagged for PartialHashtree {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PartialHashtree {}

impl Encode for PartialHashtree {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
