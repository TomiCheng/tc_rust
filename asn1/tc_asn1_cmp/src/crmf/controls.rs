//! RFC 4211 §6 `Controls`, controls that affect issuance.
//!
//! ```text
//! Controls ::= SEQUENCE SIZE (1..MAX) OF AttributeTypeAndValue
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::crmf::AttributeTypeAndValue;

/// One or more controls, such as a registration token.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Controls {
    controls: Asn1SequenceOf<AttributeTypeAndValue>,
}

impl Controls {
    /// The elements, in order. None is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<AttributeTypeAndValue>) -> Result<Self, Asn1Error> {
        if elements.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            controls: Asn1SequenceOf::new(elements),
        })
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn controls(&self) -> &[AttributeTypeAndValue] {
        self.controls.elements()
    }
}

impl DecodeContent for Controls {
    /// An empty sequence is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let controls = Asn1SequenceOf::decode_content(value, context)?;
        if controls.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { controls })
    }
}

impl DecodeInner for Controls {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, controls) = Asn1SequenceOf::<AttributeTypeAndValue>::decode_inner(buff, context)?;
        if controls.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((len, Self { controls }))
    }
}

impl EncodeContent for Controls {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.controls.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.controls.encode_content(rules, out)
    }
}

impl Decode for Controls {}

impl Tagged for Controls {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Controls {}

impl Encode for Controls {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
