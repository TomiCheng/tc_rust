//! RFC 5126 §6.2.1 `CompleteCertificateRefs`, the value of the
//! complete-certificate-references attribute.
//!
//! ```text
//! CompleteCertificateRefs ::= SEQUENCE OF OtherCertID
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::OtherCertId;

/// The CA certificates used to validate the signature, by hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CompleteCertificateRefs {
    refs: Asn1SequenceOf<OtherCertId>,
}

impl CompleteCertificateRefs {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<OtherCertId>) -> Self {
        Self {
            refs: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn refs(&self) -> &[OtherCertId] {
        self.refs.elements()
    }
}

impl DecodeContent for CompleteCertificateRefs {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let refs = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { refs })
    }
}

impl DecodeInner for CompleteCertificateRefs {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, refs) = Asn1SequenceOf::<OtherCertId>::decode_inner(buff, context)?;
        Ok((len, Self { refs }))
    }
}

impl EncodeContent for CompleteCertificateRefs {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.refs.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.refs.encode_content(rules, out)
    }
}

impl Decode for CompleteCertificateRefs {}

impl Tagged for CompleteCertificateRefs {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CompleteCertificateRefs {}

impl Encode for CompleteCertificateRefs {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
