//! RFC 4210 §5.3.22, one entry of a polling response.
//!
//! ```text
//! SEQUENCE {
//!     certReqId  INTEGER,
//!     checkAfter INTEGER,  -- time in seconds
//!     reason     PKIFreeText OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::PkiFreeText;

/// The request, how long to wait, and why.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PollRep {
    cert_req_id: Asn1Integer,
    check_after: Asn1Integer,
    reason: Option<PkiFreeText>,
}

impl PollRep {
    /// The request and the wait, without a reason.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_req_id: Asn1Integer, check_after: Asn1Integer) -> Self {
        Self {
            cert_req_id,
            check_after,
            reason: None,
        }
    }

    /// Sets the reason.
    /// Variable time: branches only on the encoding structure.
    pub fn with_reason(mut self, reason: PkiFreeText) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Returns the identifier of the request.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req_id(&self) -> &Asn1Integer {
        &self.cert_req_id
    }

    /// Returns how many seconds to wait before polling again.
    /// Variable time: branches only on the encoding structure.
    pub fn check_after(&self) -> &Asn1Integer {
        &self.check_after
    }

    /// Returns the reason, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn reason(&self) -> Option<&PkiFreeText> {
        self.reason.as_ref()
    }
}

impl DecodeContent for PollRep {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_req_id = fields.get()?;
        let check_after = fields.get()?;
        let reason = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_req_id,
            check_after,
            reason,
        };
        Ok(value)
    }
}

impl DecodeInner for PollRep {
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

impl EncodeContent for PollRep {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_req_id.encoded_len(rules)
            + self.check_after.encoded_len(rules)
            + self.reason.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_req_id.encode(rules, out)?;
        at += self.check_after.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.reason {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PollRep {}

impl Tagged for PollRep {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PollRep {}

impl Encode for PollRep {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
