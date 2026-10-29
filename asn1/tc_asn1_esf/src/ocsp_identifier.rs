//! RFC 5126 §5.7.4.1 `OcspIdentifier`, an OCSP response by responder and time.
//!
//! ```text
//! OcspIdentifier ::= SEQUENCE {
//!     ocspResponderID ResponderID,     -- As in OCSP response data
//!     producedAt      GeneralizedTime  -- As in OCSP response data
//! }
//! ```

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_ocsp::ResponderId;

/// The responder and production time of an OCSP response.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspIdentifier {
    ocsp_responder_id: ResponderId,
    produced_at: Asn1GeneralizedTime,
}

impl OcspIdentifier {
    /// The responder and time.
    /// Variable time: branches only on the encoding structure.
    pub fn new(ocsp_responder_id: ResponderId, produced_at: Asn1GeneralizedTime) -> Self {
        Self {
            ocsp_responder_id,
            produced_at,
        }
    }

    /// Returns the responder.
    /// Variable time: branches only on the encoding structure.
    pub fn ocsp_responder_id(&self) -> &ResponderId {
        &self.ocsp_responder_id
    }

    /// Returns when the response was signed.
    /// Variable time: branches only on the encoding structure.
    pub fn produced_at(&self) -> &Asn1GeneralizedTime {
        &self.produced_at
    }
}

impl DecodeContent for OcspIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let ocsp_responder_id = fields.get()?;
        let produced_at = fields.get()?;
        fields.end()?;
        let value = Self {
            ocsp_responder_id,
            produced_at,
        };
        Ok(value)
    }
}

impl DecodeInner for OcspIdentifier {
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

impl EncodeContent for OcspIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.ocsp_responder_id.encoded_len(rules) + self.produced_at.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.ocsp_responder_id.encode(rules, out)?;
        at += self.produced_at.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for OcspIdentifier {}

impl Tagged for OcspIdentifier {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OcspIdentifier {}

impl Encode for OcspIdentifier {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
