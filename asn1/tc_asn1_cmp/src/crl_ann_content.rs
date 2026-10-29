//! RFC 4210 §5.3.16 `CRLAnnContent`, the body of a CRL announcement.
//!
//! ```text
//! CRLAnnContent ::= SEQUENCE OF CertificateList
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::crl::CertificateList;

/// The CRLs announced.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlAnnContent {
    crls: Asn1SequenceOf<CertificateList>,
}

impl CrlAnnContent {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<CertificateList>) -> Self {
        Self {
            crls: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn crls(&self) -> &[CertificateList] {
        self.crls.elements()
    }
}

impl DecodeContent for CrlAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let crls = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { crls })
    }
}

impl DecodeInner for CrlAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, crls) = Asn1SequenceOf::<CertificateList>::decode_inner(buff, context)?;
        Ok((len, Self { crls }))
    }
}

impl EncodeContent for CrlAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.crls.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.crls.encode_content(rules, out)
    }
}

impl Decode for CrlAnnContent {}

impl Tagged for CrlAnnContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlAnnContent {}

impl Encode for CrlAnnContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
