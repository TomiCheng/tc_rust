//! RFC 6960 §4.2.1 `OCSPResponse`.
//!
//! ```text
//! OCSPResponse ::= SEQUENCE {
//!     responseStatus OCSPResponseStatus,
//!     responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

use crate::{OcspResponseStatus, ResponseBytes};

/// The status of the request and, when it succeeded, the response.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OcspResponse {
    response_status: OcspResponseStatus,
    response_bytes: Option<ResponseBytes>,
}

impl OcspResponse {
    /// A status without a response, as an error status is sent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(response_status: OcspResponseStatus) -> Self {
        Self {
            response_status,
            response_bytes: None,
        }
    }

    /// Sets the response, which a successful status carries.
    /// Variable time: branches only on the encoding structure.
    pub fn with_response_bytes(mut self, response_bytes: ResponseBytes) -> Self {
        self.response_bytes = Some(response_bytes);
        self
    }

    /// Returns the status of the request.
    /// Variable time: branches only on the encoding structure.
    pub fn response_status(&self) -> &OcspResponseStatus {
        &self.response_status
    }

    /// Returns the response, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn response_bytes(&self) -> Option<&ResponseBytes> {
        self.response_bytes.as_ref()
    }
}

impl DecodeContent for OcspResponse {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let response_status = fields.get()?;
        let response_bytes = fields.get_explicit_opt::<ResponseBytes>([0xa0])?;
        fields.end()?;
        let value = Self {
            response_status,
            response_bytes,
        };
        Ok(value)
    }
}

impl DecodeInner for OcspResponse {
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

impl EncodeContent for OcspResponse {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.response_status.encoded_len(rules)
            + self
                .response_bytes
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.response_status.encode(rules, out)?;
        if let Some(v) = &self.response_bytes {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OcspResponse {}

impl Tagged for OcspResponse {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OcspResponse {}

impl Encode for OcspResponse {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
