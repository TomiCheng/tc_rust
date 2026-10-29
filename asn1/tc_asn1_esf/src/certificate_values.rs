//! RFC 5126 §6.3.3 `CertificateValues`, the value of the certificate-values
//! attribute.
//!
//! ```text
//! CertificateValues ::= SEQUENCE OF Certificate
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::cert::Certificate;

/// The certificates used to validate the signature.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertificateValues {
    certificates: Asn1SequenceOf<Certificate>,
}

impl CertificateValues {
    /// The elements, in order.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<Certificate>) -> Self {
        Self {
            certificates: Asn1SequenceOf::new(elements),
        }
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn certificates(&self) -> &[Certificate] {
        self.certificates.elements()
    }
}

impl DecodeContent for CertificateValues {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let certificates = Asn1SequenceOf::decode_content(value, context)?;
        Ok(Self { certificates })
    }
}

impl DecodeInner for CertificateValues {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, certificates) = Asn1SequenceOf::<Certificate>::decode_inner(buff, context)?;
        Ok((len, Self { certificates }))
    }
}

impl EncodeContent for CertificateValues {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.certificates.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.certificates.encode_content(rules, out)
    }
}

impl Decode for CertificateValues {}

impl Tagged for CertificateValues {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertificateValues {}

impl Encode for CertificateValues {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
