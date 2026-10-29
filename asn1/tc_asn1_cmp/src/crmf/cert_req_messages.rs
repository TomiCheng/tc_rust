//! RFC 4211 §3 `CertReqMessages`, the body of a certificate request.
//!
//! ```text
//! CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1SequenceOf, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::crmf::CertReqMsg;

/// One or more requests.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertReqMessages {
    messages: Asn1SequenceOf<CertReqMsg>,
}

impl CertReqMessages {
    /// The elements, in order. None is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    pub fn new(elements: Vec<CertReqMsg>) -> Result<Self, Asn1Error> {
        if elements.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            messages: Asn1SequenceOf::new(elements),
        })
    }

    /// Returns the elements in order.
    /// Variable time: branches only on the encoding structure.
    pub fn messages(&self) -> &[CertReqMsg] {
        self.messages.elements()
    }
}

impl DecodeContent for CertReqMessages {
    /// An empty sequence is `MalformedValue`.
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let messages = Asn1SequenceOf::decode_content(value, context)?;
        if messages.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self { messages })
    }
}

impl DecodeInner for CertReqMessages {
    /// Variable time: branches only on the encoding structure.
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let (len, messages) = Asn1SequenceOf::<CertReqMsg>::decode_inner(buff, context)?;
        if messages.elements().is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok((len, Self { messages }))
    }
}

impl EncodeContent for CertReqMessages {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.messages.content_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.messages.encode_content(rules, out)
    }
}

impl Decode for CertReqMessages {}

impl Tagged for CertReqMessages {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertReqMessages {}

impl Encode for CertReqMessages {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
