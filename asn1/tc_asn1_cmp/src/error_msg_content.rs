//! RFC 4210 §5.3.21 `ErrorMsgContent`, the body of an error message.
//!
//! ```text
//! ErrorMsgContent ::= SEQUENCE {
//!     pKIStatusInfo PKIStatusInfo,
//!     errorCode     INTEGER     OPTIONAL,
//!     errorDetails  PKIFreeText OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Integer, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext,
    Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{PkiFreeText, PkiStatusInfo};

/// The status, an implementation-specific code, and details.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ErrorMsgContent {
    pki_status_info: PkiStatusInfo,
    error_code: Option<Asn1Integer>,
    error_details: Option<PkiFreeText>,
}

impl ErrorMsgContent {
    /// A status alone.
    /// Variable time: branches only on the encoding structure.
    pub fn new(pki_status_info: PkiStatusInfo) -> Self {
        Self {
            pki_status_info,
            error_code: None,
            error_details: None,
        }
    }

    /// Sets an implementation-specific code.
    /// Variable time: branches only on the encoding structure.
    pub fn with_error_code(mut self, error_code: Asn1Integer) -> Self {
        self.error_code = Some(error_code);
        self
    }

    /// Sets the details.
    /// Variable time: branches only on the encoding structure.
    pub fn with_error_details(mut self, error_details: PkiFreeText) -> Self {
        self.error_details = Some(error_details);
        self
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn pki_status_info(&self) -> &PkiStatusInfo {
        &self.pki_status_info
    }

    /// Returns the implementation-specific code, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn error_code(&self) -> Option<&Asn1Integer> {
        self.error_code.as_ref()
    }

    /// Returns the details, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn error_details(&self) -> Option<&PkiFreeText> {
        self.error_details.as_ref()
    }
}

impl DecodeContent for ErrorMsgContent {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let pki_status_info = fields.get()?;
        let error_code = fields.get_opt()?;
        let error_details = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            pki_status_info,
            error_code,
            error_details,
        };
        Ok(value)
    }
}

impl DecodeInner for ErrorMsgContent {
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

impl EncodeContent for ErrorMsgContent {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.pki_status_info.encoded_len(rules)
            + self.error_code.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self
                .error_details
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.pki_status_info.encode(rules, out)?;
        if let Some(v) = &self.error_code {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.error_details {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for ErrorMsgContent {}

impl Tagged for ErrorMsgContent {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ErrorMsgContent {}

impl Encode for ErrorMsgContent {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
