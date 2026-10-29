//! RFC 4211 §5 `CertRequest`, one certificate request.
//!
//! ```text
//! CertRequest ::= SEQUENCE {
//!     certReqId    INTEGER,       -- ID for matching request and reply
//!     certTemplate CertTemplate,  -- Selected fields of cert to be issued
//!     controls     Controls OPTIONAL } -- Attributes affecting issuance
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::crmf::{CertTemplate, Controls};

/// A request identifier, the certificate asked for, and controls.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertRequest {
    cert_req_id: Asn1Integer,
    cert_template: CertTemplate,
    controls: Option<Controls>,
}

impl CertRequest {
    /// The identifier and template, without controls.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_req_id: Asn1Integer, cert_template: CertTemplate) -> Self {
        Self {
            cert_req_id,
            cert_template,
            controls: None,
        }
    }

    /// Sets the controls.
    /// Variable time: branches only on the encoding structure.
    pub fn with_controls(mut self, controls: Controls) -> Self {
        self.controls = Some(controls);
        self
    }

    /// Returns the identifier that pairs the request with its reply.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_req_id(&self) -> &Asn1Integer {
        &self.cert_req_id
    }

    /// Returns the certificate asked for.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_template(&self) -> &CertTemplate {
        &self.cert_template
    }

    /// Returns the controls, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn controls(&self) -> Option<&Controls> {
        self.controls.as_ref()
    }
}

impl DecodeContent for CertRequest {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_req_id = fields.get()?;
        let cert_template = fields.get()?;
        let controls = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_req_id,
            cert_template,
            controls,
        };
        Ok(value)
    }
}

impl DecodeInner for CertRequest {
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

impl EncodeContent for CertRequest {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_req_id.encoded_len(rules)
            + self.cert_template.encoded_len(rules)
            + self.controls.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_req_id.encode(rules, out)?;
        at += self.cert_template.encode(rules, &mut out[at..])?;
        if let Some(v) = &self.controls {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertRequest {}

impl Tagged for CertRequest {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertRequest {}

impl Encode for CertRequest {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
