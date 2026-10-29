//! RFC 4210 §5.3.19 `InfoTypeAndValue`, one item of general information.
//!
//! ```text
//! InfoTypeAndValue ::= SEQUENCE {
//!     infoType  OBJECT IDENTIFIER,
//!     infoValue ANY DEFINED BY infoType OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// An information type, often from `CmpId`, and its value kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct InfoTypeAndValue {
    info_type: Asn1Oid,
    info_value: Option<Asn1Any>,
}

impl InfoTypeAndValue {
    /// A type without a value, as a request for it.
    /// Variable time: branches only on the encoding structure.
    pub fn new(info_type: Asn1Oid) -> Self {
        Self {
            info_type,
            info_value: None,
        }
    }

    /// Sets the value.
    /// Variable time: branches only on the encoding structure.
    pub fn with_info_value(mut self, info_value: Asn1Any) -> Self {
        self.info_value = Some(info_value);
        self
    }

    /// Returns the type.
    /// Variable time: branches only on the encoding structure.
    pub fn info_type(&self) -> &Asn1Oid {
        &self.info_type
    }

    /// Returns the value, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn info_value(&self) -> Option<&Asn1Any> {
        self.info_value.as_ref()
    }
}

impl DecodeContent for InfoTypeAndValue {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let info_type = fields.get()?;
        let info_value = fields.get_any_opt()?;
        fields.end()?;
        let value = Self {
            info_type,
            info_value,
        };
        Ok(value)
    }
}

impl DecodeInner for InfoTypeAndValue {
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

impl EncodeContent for InfoTypeAndValue {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.info_type.encoded_len(rules)
            + self.info_value.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.info_type.encode(rules, out)?;
        if let Some(v) = &self.info_value {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for InfoTypeAndValue {}

impl Tagged for InfoTypeAndValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for InfoTypeAndValue {}

impl Encode for InfoTypeAndValue {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
