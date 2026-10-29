//! RFC 4210 §5.3.4 `CertRepMessage`, the body of a certificate response.
//!
//! ```text
//! CertRepMessage ::= SEQUENCE {
//!     caPubs   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate OPTIONAL,
//!     response SEQUENCE OF CertResponse }
//! ```
//!
//! The module uses explicit tags.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1Ref, Asn1SequenceOf, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::{CertResponse, CmpCertificate};

/// CA certificates to trust and one response per request.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertRepMessage {
    ca_pubs: Option<Asn1SequenceOf<CmpCertificate>>,
    response: Asn1SequenceOf<CertResponse>,
}

impl CertRepMessage {
    /// The responses, without CA certificates.
    /// Variable time: branches only on the encoding structure.
    pub fn new(response: Vec<CertResponse>) -> Self {
        Self {
            ca_pubs: None,
            response: Asn1SequenceOf::new(response),
        }
    }

    /// Sets CA certificates for the requester to trust.
    /// Variable time: branches only on the encoding structure.
    pub fn with_ca_pubs(mut self, ca_pubs: Vec<CmpCertificate>) -> Self {
        self.ca_pubs = Some(Asn1SequenceOf::new(ca_pubs));
        self
    }

    /// Returns the CA certificates, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn ca_pubs(&self) -> Option<&[CmpCertificate]> {
        self.ca_pubs.as_ref().map(Asn1SequenceOf::elements)
    }

    /// Returns the responses in order.
    /// Variable time: branches only on the encoding structure.
    pub fn response(&self) -> &[CertResponse] {
        self.response.elements()
    }
}

impl DecodeContent for CertRepMessage {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let ca_pubs = fields.get_explicit_opt::<Asn1SequenceOf<CmpCertificate>>([0xa1])?;
        let response = fields.get()?;
        fields.end()?;
        let value = Self { ca_pubs, response };
        Ok(value)
    }
}

impl DecodeInner for CertRepMessage {
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

impl EncodeContent for CertRepMessage {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.ca_pubs
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
            + self.response.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.ca_pubs {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        at += self.response.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for CertRepMessage {}

impl Tagged for CertRepMessage {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertRepMessage {}

impl Encode for CertRepMessage {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
