//! SEQUENCE OF: an [`Asn1Constructed`] under tag 30, written in the stored order.

use alloc::vec::Vec;

use super::cer_common::constructed_tag;
use crate::traits::encode::{default_encode, default_encoded_len};
use crate::{
    Asn1Constructed, Asn1Error, Decode, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions,
};

/// A homogeneous SEQUENCE OF. Order is significant, so every rule set writes
/// the elements as stored.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1SequenceOf<T> {
    elements: Asn1Constructed<T>,
}

impl<T> Asn1SequenceOf<T> {
    pub const TAG: &'static [u8] = super::tag::SEQUENCE;

    pub fn new(elements: Vec<T>) -> Self {
        Self {
            elements: Asn1Constructed::new(Self::TAG, elements),
        }
    }

    pub fn elements(&self) -> &[T] {
        self.elements.items()
    }

    pub fn into_elements(self) -> Vec<T> {
        self.elements.into_items()
    }
}

impl<T: DecodeInner> DecodeInner for Asn1SequenceOf<T> {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (used, elements) = Asn1Constructed::decode_inner(buff, context)?;
        if elements.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        Ok((used, Self { elements }))
    }
}

impl<T: DecodeInner> Decode for Asn1SequenceOf<T> {}

impl<T: Encode> EncodeContent for Asn1SequenceOf<T> {
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.elements.content_len(rules)
    }

    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.elements.encode_content(rules, out)
    }
}

/// The default header with the constructed bit forced on, as for [`Asn1Constructed`].
impl<T: Encode> EncodeTagged for Asn1SequenceOf<T> {
    fn encoded_len_tagged(&self, tag: &[u8], rules: &EncodingOptions) -> usize {
        default_encoded_len(self, &constructed_tag(tag), rules)
    }

    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        default_encode(self, &constructed_tag(tag), rules, out)
    }
}

impl<T: Encode> Encode for Asn1SequenceOf<T> {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
