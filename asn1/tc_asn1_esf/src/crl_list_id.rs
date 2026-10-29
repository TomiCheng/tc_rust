//! RFC 5126 §5.7.4.1 `CRLListID`, the CRLs used to validate.
//!
//! ```text
//! CRLListID ::= SEQUENCE {
//!     crls SEQUENCE OF CrlValidatedID }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::CrlValidatedId;

/// The CRLs, by hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlListId {
    crls: Asn1SequenceOf<CrlValidatedId>,
}

impl CrlListId {
    /// The CRLs.
    /// Variable time: branches only on the encoding structure.
    pub fn new(crls: Vec<CrlValidatedId>) -> Self {
        Self {
            crls: Asn1SequenceOf::new(crls),
        }
    }

    /// Returns the CRLs in order.
    /// Variable time: branches only on the encoding structure.
    pub fn crls(&self) -> &[CrlValidatedId] {
        self.crls.elements()
    }
}

impl DecodeContent for CrlListId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let crls = fields.get()?;
        fields.end()?;
        let value = Self { crls };
        Ok(value)
    }
}

impl DecodeInner for CrlListId {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = Asn1Ref::parse(buff, context)?.assert_tag(Self::TAG)?;
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl EncodeContent for CrlListId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crls.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.crls.encode(rules, out)?;
        Ok(at)
    }
}

impl Decode for CrlListId {}

impl Tagged for CrlListId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlListId {}

impl Encode for CrlListId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
