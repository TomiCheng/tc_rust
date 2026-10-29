//! RFC 6960 §4.2.1 `ResponseData`, the signed part of a basic response.
//!
//! ```text
//! ResponseData ::= SEQUENCE {
//!     version            [0] EXPLICIT Version DEFAULT v1,
//!     responderID            ResponderID,
//!     producedAt             GeneralizedTime,
//!     responses              SEQUENCE OF SingleResponse,
//!     responseExtensions [1] EXPLICIT Extensions OPTIONAL }
//! ```
//!
//! A version written as its default v1 is kept and written back, as Bouncy
//! Castle does, so a signature over the encoding still verifies.

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Error, Asn1GeneralizedTime, Asn1Integer, Asn1Ref, Asn1SequenceOf, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;

use crate::{ResponderId, SingleResponse};

/// Who responds, when the response was signed, one response per certificate,
/// and extensions such as the nonce echoed back.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ResponseData {
    version: Option<Asn1Integer>,
    responder_id: ResponderId,
    produced_at: Asn1GeneralizedTime,
    responses: Asn1SequenceOf<SingleResponse>,
    response_extensions: Option<Extensions>,
}

impl ResponseData {
    /// The responder, the signing time and the responses, as version 1 without
    /// extensions.
    /// Variable time: branches only on the encoding structure.
    pub fn new(
        responder_id: ResponderId,
        produced_at: Asn1GeneralizedTime,
        responses: Vec<SingleResponse>,
    ) -> Self {
        Self {
            version: None,
            responder_id,
            produced_at,
            responses: Asn1SequenceOf::new(responses),
            response_extensions: None,
        }
    }

    /// Writes the version, even v1 (0), which is otherwise omitted.
    /// Variable time: branches only on the encoding structure.
    pub fn with_version(mut self, version: Asn1Integer) -> Self {
        self.version = Some(version);
        self
    }

    /// Sets the extensions of the whole response, such as the nonce.
    /// Variable time: branches only on the encoding structure.
    pub fn with_response_extensions(mut self, response_extensions: Extensions) -> Self {
        self.response_extensions = Some(response_extensions);
        self
    }

    /// Returns the version, v1 (0) when absent.
    /// Variable time: branches only on the encoding structure.
    pub fn version(&self) -> Asn1Integer {
        self.version.clone().unwrap_or_else(|| 0.into())
    }

    /// Returns the responder.
    /// Variable time: branches only on the encoding structure.
    pub fn responder_id(&self) -> &ResponderId {
        &self.responder_id
    }

    /// Returns when the response was signed.
    /// Variable time: branches only on the encoding structure.
    pub fn produced_at(&self) -> &Asn1GeneralizedTime {
        &self.produced_at
    }

    /// Returns the responses in order.
    /// Variable time: branches only on the encoding structure.
    pub fn responses(&self) -> &[SingleResponse] {
        self.responses.elements()
    }

    /// Returns the extensions of the whole response, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn response_extensions(&self) -> Option<&Extensions> {
        self.response_extensions.as_ref()
    }
}

impl DecodeContent for ResponseData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let version = fields.get_explicit_opt::<Asn1Integer>([0xa0])?;
        let responder_id = fields.get()?;
        let produced_at = fields.get()?;
        let responses = fields.get()?;
        let response_extensions = fields.get_explicit_opt::<Extensions>([0xa1])?;
        fields.end()?;
        let value = Self {
            version,
            responder_id,
            produced_at,
            responses,
            response_extensions,
        };
        Ok(value)
    }
}

impl DecodeInner for ResponseData {
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

impl EncodeContent for ResponseData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.version
            .as_ref()
            .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
            + self.responder_id.encoded_len(rules)
            + self.produced_at.encoded_len(rules)
            + self.responses.encoded_len(rules)
            + self
                .response_extensions
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa1], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.version {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        at += self.responder_id.encode(rules, &mut out[at..])?;
        at += self.produced_at.encode(rules, &mut out[at..])?;
        at += self.responses.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.response_extensions {
            at += Explicit::new(&[0xa1], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for ResponseData {}

impl Tagged for ResponseData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ResponseData {}

impl Encode for ResponseData {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
