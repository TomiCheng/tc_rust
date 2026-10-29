//! RFC 4210 §5.3.18 `CertConfirmContent`, the body of a certificate confirmation.
//!
//! ```text
//! CertConfirmContent ::= SEQUENCE OF CertStatus
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::CertStatus;

/// One status per certificate issued.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertConfirmContent {
    statuses: Asn1SequenceOf<CertStatus>,
}

impl CertConfirmContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<CertStatus>) -> Self {
        Self {
            statuses: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn statuses(&self) -> &[CertStatus] {
        self.statuses.elements()
    }
}

impl DecodeContent for CertConfirmContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let statuses = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { statuses })
    }
}

impl DecodeInner for CertConfirmContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, statuses) = Asn1SequenceOf::<CertStatus>::decode_inner(buff, context)?;
        Ok((len, Self { statuses }))
    }
}

impl EncodeContent for CertConfirmContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.statuses.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.statuses.encode_content(rules, out)
    }
}

impl Decode for CertConfirmContent {}

impl Tagged for CertConfirmContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertConfirmContent {}

impl Encode for CertConfirmContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
