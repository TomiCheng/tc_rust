//! RFC 5544 `TimeStampAndCRL`, one time stamp and the CRL that shows its
//! authority's certificate was valid.
//!
//! ```text
//! TimeStampAndCRL ::= SEQUENCE {
//!     timeStamp   TimeStampToken,          -- according to RFC 3161
//!     crl         CertificateList OPTIONAL -- according to RFC 5280 }
//! TimeStampToken ::= ContentInfo
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::crl::CertificateList;

use crate::content::ContentInfo;

/// A time-stamp token, a signed-data `ContentInfo`, with an optional CRL.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct TimeStampAndCrl {
    time_stamp: ContentInfo,
    crl: Option<CertificateList>,
}

impl TimeStampAndCrl {
    /// A time-stamp token without a CRL.
    /// Variable time: branches only on the encoding structure.
    pub fn new(time_stamp: ContentInfo) -> Self {
        Self {
            time_stamp,
            crl: None,
        }
    }

    /// Adds the CRL that covers the time-stamp authority.
    /// Variable time: branches only on the encoding structure.
    pub fn with_crl(mut self, crl: CertificateList) -> Self {
        self.crl = Some(crl);
        self
    }

    /// Returns the time-stamp token.
    /// Variable time: branches only on the encoding structure.
    pub fn time_stamp(&self) -> &ContentInfo {
        &self.time_stamp
    }

    /// Returns the CRL, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn crl(&self) -> Option<&CertificateList> {
        self.crl.as_ref()
    }
}

impl DecodeContent for TimeStampAndCrl {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let time_stamp = fields.get()?;
        let crl = fields.get_opt()?;
        fields.end()?;
        let value = Self { time_stamp, crl };
        Ok(value)
    }
}

impl DecodeInner for TimeStampAndCrl {
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

impl EncodeContent for TimeStampAndCrl {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.time_stamp.encoded_len(rules) + self.crl.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.time_stamp.encode(rules, out)?;
        if let Some(v) = &self.crl {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for TimeStampAndCrl {}

impl Tagged for TimeStampAndCrl {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for TimeStampAndCrl {}

impl Encode for TimeStampAndCrl {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
