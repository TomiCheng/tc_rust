//! RFC 4210 §5.2.3 `PKIStatusInfo`, the status of a CMP or time-stamp
//! response.
//!
//! ```text
//! PKIStatusInfo ::= SEQUENCE {
//!     status       PKIStatus,
//!     statusString PKIFreeText    OPTIONAL,
//!     failInfo     PKIFailureInfo OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

use crate::{PkiFailureInfo, PkiFreeText, PkiStatus};

/// The status, text explaining it, and the reasons for a failure.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PkiStatusInfo {
    status: PkiStatus,
    status_string: Option<PkiFreeText>,
    fail_info: Option<PkiFailureInfo>,
}

impl PkiStatusInfo {
    /// A status without text or failure information.
    /// Variable time: branches only on the encoding structure.
    pub fn new(status: PkiStatus) -> Self {
        Self {
            status,
            status_string: None,
            fail_info: None,
        }
    }

    /// Sets the text explaining the status.
    /// Variable time: branches only on the encoding structure.
    pub fn with_status_string(mut self, status_string: PkiFreeText) -> Self {
        self.status_string = Some(status_string);
        self
    }

    /// Sets the reasons for a failure.
    /// Variable time: branches only on the encoding structure.
    pub fn with_fail_info(mut self, fail_info: PkiFailureInfo) -> Self {
        self.fail_info = Some(fail_info);
        self
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn status(&self) -> &PkiStatus {
        &self.status
    }

    /// Returns the text explaining the status, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn status_string(&self) -> Option<&PkiFreeText> {
        self.status_string.as_ref()
    }

    /// Returns the reasons for a failure, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn fail_info(&self) -> Option<&PkiFailureInfo> {
        self.fail_info.as_ref()
    }
}

impl DecodeContent for PkiStatusInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let status = fields.get()?;
        let status_string = fields.get_opt()?;
        let fail_info = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            status,
            status_string,
            fail_info,
        };
        Ok(value)
    }
}

impl DecodeInner for PkiStatusInfo {
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

impl EncodeContent for PkiStatusInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.status.encoded_len(rules)
            + self
                .status_string
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
            + self.fail_info.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.status.encode(rules, out)?;
        if let Some(v) = &self.status_string {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.fail_info {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for PkiStatusInfo {}

impl Tagged for PkiStatusInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for PkiStatusInfo {}

impl Encode for PkiStatusInfo {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
