//! RFC 5652 §3 `ContentInfo`, the outermost wrapper of every CMS message.
//!
//! ```text
//! ContentInfo ::= SEQUENCE {
//!     contentType ContentType,
//!     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
//! ```
//!
//! RFC 5652 makes `content` mandatory; PKCS #7 and Bouncy Castle allow it to be
//! absent, as for detached data, so this type does too.

use tc_asn1::{
    Asn1Any, Asn1Error, Asn1Oid, Asn1Ref, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Explicit, Tagged, tag,
};

/// A content type and its content, kept as the octets it was read with.
///
/// ```
/// use tc_asn1::{Asn1Any, Decode, DecodingOptions, Encode, EncodingOptions, tag};
/// use tc_asn1_cms::content::{ContentInfo, ContentType};
///
/// // A Data message: the content is an OCTET STRING.
/// let data = ContentInfo::new(ContentType::DATA.oid())
///     .with_content(Asn1Any::primitive(tag::OCTET_STRING, b"hello"));
/// let der = data.encode_to_vec(&EncodingOptions::DER)?;
///
/// let back = ContentInfo::decode_der(&der, &DecodingOptions::default())?.1;
/// assert_eq!(ContentType::from_oid(back.content_type()), Some(ContentType::DATA));
/// assert_eq!(back.content().unwrap().as_ref().value(), b"hello");
/// # Ok::<(), tc_asn1::Asn1Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ContentInfo {
    content_type: Asn1Oid,
    content: Option<Asn1Any>,
}

impl ContentInfo {
    /// A content type without content, as for detached data.
    /// Variable time: branches only on the encoding structure.
    pub fn new(content_type: Asn1Oid) -> Self {
        Self {
            content_type,
            content: None,
        }
    }

    /// Adds the content, which should be what the content type defines.
    /// Variable time: branches only on the encoding structure.
    pub fn with_content(mut self, content: Asn1Any) -> Self {
        self.content = Some(content);
        self
    }

    /// Returns the content type.
    /// Variable time: branches only on the encoding structure.
    pub fn content_type(&self) -> &Asn1Oid {
        &self.content_type
    }

    /// Returns the content, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn content(&self) -> Option<&Asn1Any> {
        self.content.as_ref()
    }
}

impl DecodeContent for ContentInfo {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let content_type = fields.get()?;
        let content = fields.get_explicit_opt::<Asn1Any>([0xa0])?;
        fields.end()?;
        Ok(Self {
            content_type,
            content,
        })
    }
}

impl DecodeInner for ContentInfo {
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

impl EncodeContent for ContentInfo {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.content_type.encoded_len(rules)
            + self
                .content
                .as_ref()
                .map_or(0, |v| Explicit::new(&[0xa0], v).encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.content_type.encode(rules, out)?;
        if let Some(v) = &self.content {
            at += Explicit::new(&[0xa0], v).encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for ContentInfo {}

impl Tagged for ContentInfo {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ContentInfo {}

impl Encode for ContentInfo {
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

    use super::ContentInfo;
    use crate::content::ContentType;

    const DATA_HI: &[u8] = &[
        0x30, 0x11, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0, 0x04,
        0x04, 0x02, b'h', b'i',
    ];

    #[test]
    fn a_data_message_wraps_its_octet_string_in_an_explicit_zero_tag() {
        let value = ContentInfo::new(ContentType::DATA.oid())
            .with_content(Asn1Any::primitive(tag::OCTET_STRING, b"hi"));
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), DATA_HI);
        assert_eq!(
            ContentInfo::decode_der(DATA_HI, &DecodingOptions::default())
                .unwrap()
                .1,
            value
        );
    }

    #[test]
    fn detached_content_is_absent_and_indefinite_lengths_decode_under_ber() {
        let detached = ContentInfo::new(ContentType::SIGNED_DATA.oid());
        let wire = detached.encode_to_vec(&EncodingOptions::DER).unwrap();
        assert_eq!(wire.len(), 2 + 11);
        assert_eq!(
            ContentInfo::decode_der(&wire, &DecodingOptions::default())
                .unwrap()
                .1
                .content(),
            None
        );
        // The same Data message with indefinite outer and wrapper lengths.
        let ber = [
            0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, 0xa0,
            0x80, 0x04, 0x02, b'h', b'i', 0, 0, 0, 0,
        ];
        let value = ContentInfo::decode(&ber, &DecodingOptions::default())
            .unwrap()
            .1;
        assert_eq!(value.content().unwrap().raw(), [0x04, 0x02, b'h', b'i']);
        assert_eq!(value.encode_to_vec(&EncodingOptions::DER).unwrap(), DATA_HI);
    }

    #[test]
    fn a_missing_type_a_wrong_context_tag_and_trailing_fields_are_rejected() {
        for (wire, error) in [
            (&b"\x30\x00"[..], Asn1Error::Truncated),
            (&b"\x30\x04\xa0\x02\x05\x00"[..], Asn1Error::UnexpectedTag),
            (
                &b"\x30\x0f\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\xa1\x02\x05\x00"[..],
                Asn1Error::TrailingData,
            ),
        ] {
            assert_eq!(
                ContentInfo::decode_der(wire, &DecodingOptions::default()),
                Err(error)
            );
        }
    }
}
