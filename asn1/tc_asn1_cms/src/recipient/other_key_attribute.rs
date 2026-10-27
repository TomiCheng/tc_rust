//! RFC 5652 §10.2.7 `OtherKeyAttribute`, extra information that identifies a
//! recipient's key.
//!
//! ```text
//! OtherKeyAttribute ::= SEQUENCE {
//!     keyAttrId OBJECT IDENTIFIER,
//!     keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
//! ```

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// A key attribute identifier and its optional value, kept as the octets it was
/// read with.
///
/// ```
/// use tc_asn1::{Decode, DecodingOptions, Encode, EncodingOptions};
/// use tc_asn1_cms::recipient::OtherKeyAttribute;
///
/// let attribute = OtherKeyAttribute::new("1.2.3.4".parse()?);
/// let der = attribute.encode_to_vec(&EncodingOptions::DER)?;
/// assert_eq!(OtherKeyAttribute::decode_der(&der, &DecodingOptions::default())?.1, attribute);
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct OtherKeyAttribute {
    key_attr_id: Asn1Oid,
    key_attr: Option<Asn1Any>,
}

impl OtherKeyAttribute {
    /// An attribute identifier without a value.
    /// Variable time: branches only on the encoding structure.
    pub fn new(key_attr_id: Asn1Oid) -> Self {
        Self {
            key_attr_id,
            key_attr: None,
        }
    }

    /// Adds the attribute value.
    /// Variable time: branches only on the encoding structure.
    pub fn with_key_attr(mut self, key_attr: Asn1Any) -> Self {
        self.key_attr = Some(key_attr);
        self
    }

    /// Returns the attribute identifier.
    /// Variable time: branches only on the encoding structure.
    pub fn key_attr_id(&self) -> &Asn1Oid {
        &self.key_attr_id
    }

    /// Returns the attribute value, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn key_attr(&self) -> Option<&Asn1Any> {
        self.key_attr.as_ref()
    }
}

impl DecodeContent for OtherKeyAttribute {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let key_attr_id = fields.get()?;
        let key_attr = fields.get_any_opt()?;
        fields.end()?;
        Ok(Self {
            key_attr_id,
            key_attr,
        })
    }
}

impl DecodeInner for OtherKeyAttribute {
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

impl EncodeContent for OtherKeyAttribute {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.key_attr_id.encoded_len(rules)
            + self.key_attr.as_ref().map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.key_attr_id.encode(rules, out)?;
        if let Some(v) = &self.key_attr {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for OtherKeyAttribute {}

impl Tagged for OtherKeyAttribute {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for OtherKeyAttribute {}

impl Encode for OtherKeyAttribute {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use tc_asn1::{Asn1Any, Asn1Error, Decode, DecodingOptions, Encode, EncodingOptions, tag};

    use super::OtherKeyAttribute;

    #[test]
    fn the_value_may_be_absent_or_any_element_after_the_identifier() {
        let bare = OtherKeyAttribute::new("1.2.3.4".parse().unwrap());
        assert_eq!(
            bare.encode_to_vec(&EncodingOptions::DER).unwrap(),
            [0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04]
        );
        let valued = bare
            .clone()
            .with_key_attr(Asn1Any::primitive(tag::OCTET_STRING, &[7]));
        let wire = valued.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(
            wire,
            [0x30, 0x08, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x04, 0x01, 0x07]
        );
        assert_eq!(
            OtherKeyAttribute::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1,
            valued
        );
    }

    #[test]
    fn a_missing_identifier_or_a_second_value_is_rejected() {
        for (wire, error) in [
            (&b"\x30\x00"[..], Asn1Error::Truncated),
            (
                &b"\x30\x09\x06\x03\x2a\x03\x04\x05\x00\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                OtherKeyAttribute::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
