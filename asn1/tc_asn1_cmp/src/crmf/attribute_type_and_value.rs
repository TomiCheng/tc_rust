//! RFC 4211 §6 `AttributeTypeAndValue`, a registration control or information item.
//!
//! ```text
//! AttributeTypeAndValue ::= SEQUENCE {
//!     type  OBJECT IDENTIFIER,
//!     value ANY DEFINED BY type }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A control or registration item by type, its value kept as found.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct AttributeTypeAndValue {
    attribute_type: Asn1Oid,
    value: Asn1Any,
}

impl AttributeTypeAndValue {
    /// The type and its value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(attribute_type: Asn1Oid, value: Asn1Any) -> Self {
        Self {
            attribute_type,
            value,
        }
    }

    /// Returns the type, often from `CrmfId`.
    /// Variable time: branches only on the encoding structure.
    pub fn attribute_type(&self) -> &Asn1Oid {
        &self.attribute_type
    }

    /// Returns the value.
    /// Variable time: branches only on the encoding structure.
    pub fn value(&self) -> &Asn1Any {
        &self.value
    }
}

impl DecodeContent for AttributeTypeAndValue {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let attribute_type = fields.get()?;
        let value = fields.get()?;
        fields.end()?;
        let value = Self {
            attribute_type,
            value,
        };
        Ok(value)
    }
}

impl DecodeInner for AttributeTypeAndValue {
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

impl EncodeContent for AttributeTypeAndValue {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.attribute_type.encoded_len(rules) + self.value.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.attribute_type.encode(rules, out)?;
        at += self.value.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for AttributeTypeAndValue {}

impl Tagged for AttributeTypeAndValue {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for AttributeTypeAndValue {}

impl Encode for AttributeTypeAndValue {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
