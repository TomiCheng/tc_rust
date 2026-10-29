//! RFC 6960 §4.1.1 `Request`, one certificate whose status is asked.
//!
//! ```text
//! Request ::= SEQUENCE {
//!     reqCert                 CertID,
//!     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};
use tc_asn1_x509::ext::Extensions;

use crate::CertId;

/// The certificate asked about, with extensions for this one request.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Request {
    req_cert: CertId,
    single_request_extensions: Option<Extensions>,
}

impl Request {
    /// The certificate asked about, without extensions.
    /// Variable time: branches only on the encoding structure.
    pub fn new(req_cert: CertId) -> Self {
        Self {
            req_cert,
            single_request_extensions: None,
        }
    }

    /// Sets the extensions of this request, such as a service locator.
    /// Variable time: branches only on the encoding structure.
    pub fn with_single_request_extensions(mut self, single_request_extensions: Extensions) -> Self {
        self.single_request_extensions = Some(single_request_extensions);
        self
    }

    /// Returns the certificate asked about.
    /// Variable time: branches only on the encoding structure.
    pub fn req_cert(&self) -> &CertId {
        &self.req_cert
    }

    /// Returns the extensions of this request, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn single_request_extensions(&self) -> Option<&Extensions> {
        self.single_request_extensions.as_ref()
    }
}

impl DecodeContent for Request {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let req_cert = fields.get()?;
        let single_request_extensions = fields.get_explicit_opt::<Extensions>([0xa0])?;
        fields.end()?;
        let value = Self {
            req_cert,
            single_request_extensions,
        };
        Ok(value)
    }
}

impl DecodeInner for Request {
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

impl EncodeContent for Request {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.req_cert.encoded_len(rules)
            + self
                .single_request_extensions
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.req_cert.encode(rules, out)?;
        if let Some(v) = &self.single_request_extensions {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for Request {}

impl Tagged for Request {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for Request {}

impl Encode for Request {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
