//! RFC 9480 §2.17 `CRLStatus`, a CRL the requester holds.
//!
//! ```text
//! CRLStatus ::= SEQUENCE {
//!     source     CRLSource,
//!     thisUpdate Time OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Ref, Children, Decode, DecodeContent, DecodeInner, DecodingContext, Encode,
    EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};
use tc_asn1_x509::cert::Time;

use crate::CrlSource;

/// Where the CRL comes from and, optionally, its thisUpdate time.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct CrlStatus {
    source: CrlSource,
    this_update: Option<Time>,
}

impl CrlStatus {
    /// The source, without a time.
    /// Variable time: branches only on the encoding structure.
    pub fn new(source: CrlSource) -> Self {
        Self {
            source,
            this_update: None,
        }
    }

    /// Sets the thisUpdate time of the CRL held.
    /// Variable time: branches only on the encoding structure.
    pub fn with_this_update(mut self, this_update: Time) -> Self {
        self.this_update = Some(this_update);
        self
    }

    /// Returns where the CRL comes from.
    /// Variable time: branches only on the encoding structure.
    pub fn source(&self) -> &CrlSource {
        &self.source
    }

    /// Returns the thisUpdate time of the CRL held, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn this_update(&self) -> Option<&Time> {
        self.this_update.as_ref()
    }
}

impl DecodeContent for CrlStatus {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let source = fields.get()?;
        let this_update = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            source,
            this_update,
        };
        Ok(value)
    }
}

impl DecodeInner for CrlStatus {
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

impl EncodeContent for CrlStatus {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.source.encoded_len(rules)
            + self
                .this_update
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.source.encode(rules, out)?;
        if let Some(v) = &self.this_update {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for CrlStatus {}

impl Tagged for CrlStatus {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for CrlStatus {}

impl Encode for CrlStatus {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
