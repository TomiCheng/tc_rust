//! RFC 4210 §5.2.8 `POPODecKeyChallContent`, the body of a POP challenge.
//!
//! ```text
//! POPODecKeyChallContent ::= SEQUENCE OF Challenge
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::Challenge;

/// One challenge per encryption key requested.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PopoDecKeyChallContent {
    challenges: Asn1SequenceOf<Challenge>,
}

impl PopoDecKeyChallContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<Challenge>) -> Self {
        Self {
            challenges: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn challenges(&self) -> &[Challenge] {
        self.challenges.elements()
    }
}

impl DecodeContent for PopoDecKeyChallContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let challenges = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { challenges })
    }
}

impl DecodeInner for PopoDecKeyChallContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, challenges) = Asn1SequenceOf::<Challenge>::decode_inner(buff, context)?;
        Ok((len, Self { challenges }))
    }
}

impl EncodeContent for PopoDecKeyChallContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.challenges.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.challenges.encode_content(rules, out)
    }
}

impl Decode for PopoDecKeyChallContent {}

impl Tagged for PopoDecKeyChallContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PopoDecKeyChallContent {}

impl Encode for PopoDecKeyChallContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
