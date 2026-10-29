//! RFC 4998 §2.1 `CryptoInfos`, data such as certificates and CRLs that
//! help verify an evidence record.
//!
//! ```text
//! CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Attribute;

/// One or more attributes.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CryptoInfos {
    attributes: Asn1SequenceOf<Attribute>,
}

impl CryptoInfos {
    /// The elements, in order. None is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<Attribute>) -> Result<Self, Asn1Error> {
        if elements.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            attributes: Asn1SequenceOf::new(elements),
        })
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn attributes(&self) -> &[Attribute] {
        self.attributes.elements()
    }
}

impl DecodeContent for CryptoInfos {
    /// An empty sequence is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let attributes = Asn1SequenceOf::decode_content(value, context)?;
        if attributes.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { attributes })
    }
}

impl DecodeInner for CryptoInfos {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, attributes) = Asn1SequenceOf::<Attribute>::decode_inner(buff, context)?;
        if attributes.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((len, Self { attributes }))
    }
}

impl EncodeContent for CryptoInfos {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.attributes.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.attributes.encode_content(rules, out)
    }
}

impl Decode for CryptoInfos {}

impl Tagged for CryptoInfos {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CryptoInfos {}

impl Encode for CryptoInfos {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
