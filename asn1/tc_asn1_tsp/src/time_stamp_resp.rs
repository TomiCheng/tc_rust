//! RFC 3161 §2.4.2 `TimeStampResp`.
//!
//! ```text
//! TimeStampResp ::= SEQUENCE {
//!     status         PKIStatusInfo,
//!     timeStampToken TimeStampToken OPTIONAL }
//! TimeStampToken ::= ContentInfo
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_cmp::PkiStatusInfo;
use tc_asn1_cms::content::ContentInfo;

/// The status of the request and, when granted, the token: a CMS `SignedData`
/// whose content is a `TSTInfo`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TimeStampResp {
    status: PkiStatusInfo,
    time_stamp_token: Option<ContentInfo>,
}

impl TimeStampResp {
    /// A status without a token, as a rejection is sent.
    /// Variable time: branches only on the encoding structure.
    pub fn new(status: PkiStatusInfo) -> Self {
        Self {
            status,
            time_stamp_token: None,
        }
    }

    /// Sets the token, which a granted status carries.
    /// Variable time: branches only on the encoding structure.
    pub fn with_time_stamp_token(mut self, time_stamp_token: ContentInfo) -> Self {
        self.time_stamp_token = Some(time_stamp_token);
        self
    }

    /// Returns the status.
    /// Variable time: branches only on the encoding structure.
    pub fn status(&self) -> &PkiStatusInfo {
        &self.status
    }

    /// Returns the token, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn time_stamp_token(&self) -> Option<&ContentInfo> {
        self.time_stamp_token.as_ref()
    }
}

impl DecodeContent for TimeStampResp {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let status = fields.get()?;
        let time_stamp_token = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            status,
            time_stamp_token,
        };
        Ok(value)
    }
}

impl DecodeInner for TimeStampResp {
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

impl EncodeContent for TimeStampResp {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.status.encoded_len(rules)
            + self
                .time_stamp_token
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.status.encode(rules, out)?;
        if let Some(v) = &self.time_stamp_token {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for TimeStampResp {}

impl Tagged for TimeStampResp {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TimeStampResp {}

impl Encode for TimeStampResp {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
