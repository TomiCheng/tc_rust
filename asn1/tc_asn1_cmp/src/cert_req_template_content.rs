//! RFC 9480 §2.16 `CertReqTemplateContent`, the certificate request template a CA
//! offers.
//!
//! ```text
//! CertReqTemplateContent ::= SEQUENCE {
//!     certTemplate CertTemplate,
//!     keySpec      Controls OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::crmf::{CertTemplate, Controls};

/// The fields to request and, optionally, the key types to use.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CertReqTemplateContent {
    cert_template: CertTemplate,
    key_spec: Option<Controls>,
}

impl CertReqTemplateContent {
    /// The template, without a key specification.
    /// Variable time: branches only on the encoding structure.
    pub fn new(cert_template: CertTemplate) -> Self {
        Self {
            cert_template,
            key_spec: None,
        }
    }

    /// Sets the key specification.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_spec(mut self, key_spec: Controls) -> Self {
        self.key_spec = Some(key_spec);
        self
    }

    /// Returns the template.
    /// Variable time: branches only on the encoding structure.
    pub fn cert_template(&self) -> &CertTemplate {
        &self.cert_template
    }

    /// Returns the key specification, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn key_spec(&self) -> Option<&Controls> {
        self.key_spec.as_ref()
    }
}

impl DecodeContent for CertReqTemplateContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let cert_template = fields.get()?;
        let key_spec = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            cert_template,
            key_spec,
        };
        Ok(value)
    }
}

impl DecodeInner for CertReqTemplateContent {
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

impl EncodeContent for CertReqTemplateContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.cert_template.encoded_len(rules)
            + self.key_spec.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.cert_template.encode(rules, out)?;
        if let Some(v) = &self.key_spec {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CertReqTemplateContent {}

impl Tagged for CertReqTemplateContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CertReqTemplateContent {}

impl Encode for CertReqTemplateContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
