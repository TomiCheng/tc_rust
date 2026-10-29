//! RFC 2634 §2.9 `ContentHints`, the value of the content-hints attribute:
//! what the innermost signed content is.
//!
//! ```text
//! ContentHints ::= SEQUENCE {
//!     contentDescription UTF8String (SIZE (1..MAX)) OPTIONAL,
//!     contentType        ContentType }
//! ```

use tc_asn1::{
    Asn1Error, Asn1Oid, Asn1Ref, Asn1Utf8String, Children, Decode, DecodeContent, DecodeInner,
    DecodingContext, Encode, EncodeContent, EncodeTagged, EncodingOptions, Tagged, tag,
};

/// The type of the innermost content and, optionally, a description of it.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ContentHints {
    content_description: Option<Asn1Utf8String>,
    content_type: Asn1Oid,
}

impl ContentHints {
    /// The content type, without a description.
    /// Variable time: branches only on the encoding structure.
    pub fn new(content_type: Asn1Oid) -> Self {
        Self {
            content_description: None,
            content_type,
        }
    }

    /// Sets a description to show the recipient.
    /// Variable time: branches only on the encoding structure.
    pub fn with_content_description(mut self, content_description: Asn1Utf8String) -> Self {
        self.content_description = Some(content_description);
        self
    }

    /// Returns the description, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn content_description(&self) -> Option<&Asn1Utf8String> {
        self.content_description.as_ref()
    }

    /// Returns the type of the innermost content.
    /// Variable time: branches only on the encoding structure.
    pub fn content_type(&self) -> &Asn1Oid {
        &self.content_type
    }
}

impl DecodeContent for ContentHints {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let content_description = fields.get_opt()?;
        let content_type = fields.get()?;
        fields.end()?;
        let value = Self {
            content_description,
            content_type,
        };
        Ok(value)
    }
}

impl DecodeInner for ContentHints {
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

impl EncodeContent for ContentHints {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.content_description
            .as_ref()
            .map_or(0, |v| v.encoded_len(rules))
            + self.content_type.encoded_len(rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        if let Some(v) = &self.content_description {
            at += v.encode(rules, &mut out[at..])?;
        }
        at += self.content_type.encode(rules, &mut out[at..])?;
        Ok(at)
    }
}

impl Decode for ContentHints {}

impl Tagged for ContentHints {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for ContentHints {}

impl Encode for ContentHints {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
