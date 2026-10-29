//! RFC 5126 §5.7.4.1 `OcspListID`, the OCSP responses used to validate.
//!
//! ```text
//! OcspListID ::= SEQUENCE {
//!     ocspResponses SEQUENCE OF OcspResponsesID }
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::OcspResponsesId;

/// The OCSP responses.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspListId {
    ocsp_responses: Asn1SequenceOf<OcspResponsesId>,
}

impl OcspListId {
    /// The responses.
    /// Variable time: branches only on the encoding structure.
    pub fn new(ocsp_responses: Vec<OcspResponsesId>) -> Self {
        Self {
            ocsp_responses: Asn1SequenceOf::new(ocsp_responses),
        }
    }

    /// Returns the responses in order.
    /// Variable time: branches only on the encoding structure.
    pub fn ocsp_responses(&self) -> &[OcspResponsesId] {
        self.ocsp_responses.elements()
    }
}

impl DecodeContent for OcspListId {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let ocsp_responses = fields.get()?;
        fields.end()?;
        let value = Self { ocsp_responses };
        Ok(value)
    }
}

impl DecodeInner for OcspListId {
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

impl EncodeContent for OcspListId {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.ocsp_responses.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.ocsp_responses.encode(rules, out)?;
        Ok(at)
    }
}

impl Decode for OcspListId {}

impl Tagged for OcspListId {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OcspListId {}

impl Encode for OcspListId {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
