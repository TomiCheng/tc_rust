//! RFC 5126 §6.2.2 `CompleteRevocationRefs`, the value of the
//! complete-revocation-references attribute.
//!
//! ```text
//! CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::CrlOcspRef;

/// The revocation data used to validate the signature, one entry per
/// certificate.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CompleteRevocationRefs {
    refs: Asn1SequenceOf<CrlOcspRef>,
}

impl CompleteRevocationRefs {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<CrlOcspRef>) -> Self {
        Self {
            refs: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn refs(&self) -> &[CrlOcspRef] {
        self.refs.elements()
    }
}

impl DecodeContent for CompleteRevocationRefs {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let refs = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { refs })
    }
}

impl DecodeInner for CompleteRevocationRefs {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, refs) = Asn1SequenceOf::<CrlOcspRef>::decode_inner(buff, context)?;
        Ok((len, Self { refs }))
    }
}

impl EncodeContent for CompleteRevocationRefs {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.refs.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.refs.encode_content(rules, out)
    }
}

impl Decode for CompleteRevocationRefs {}

impl Tagged for CompleteRevocationRefs {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CompleteRevocationRefs {}

impl Encode for CompleteRevocationRefs {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
