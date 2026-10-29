//! RFC 4210 §5.3.22, one entry of a polling request.
//!
//! ```text
//! SEQUENCE {
//!     certReqId INTEGER }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The request to ask about.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PollReq {
    cert_req_id: Asn1Integer,
}

impl PollReq {
    /// The request identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_req_id: Asn1Integer) -> Self {
        Self { cert_req_id }
    }

    /// Returns the identifier of the request.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req_id(&self) -> &Asn1Integer {
        &self.cert_req_id
    }
}

impl DecodeContent for PollReq {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_req_id = fields.get()?;
        fields.end()?;
        let value = Self { cert_req_id };
        Ok(value)
    }
}

impl DecodeInner for PollReq {
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

impl EncodeContent for PollReq {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_req_id.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let at = self.cert_req_id.encode(rules, out)?;
        Ok(at)
    }
}

impl Decode for PollReq {}

impl Tagged for PollReq {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PollReq {}

impl Encode for PollReq {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
