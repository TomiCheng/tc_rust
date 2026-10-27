//! RFC 5544 `MetaData`, a description of time-stamped content.
//!
//! ```text
//! MetaData ::= SEQUENCE {
//!     hashProtected  BOOLEAN,
//!     fileName       UTF8String OPTIONAL,
//!     mediaType      IA5String OPTIONAL,  -- MIME type
//!     otherMetaData  Attributes OPTIONAL }
//! Attributes ::= SET SIZE(1..MAX) OF Attribute
//! ```

use alloc::vec::Vec;

use tc_asn1::{
    Asn1Boolean, Asn1Error, Asn1Ia5String, Asn1Ref, Asn1SetOf, Asn1Utf8String, Children, Decode,
    DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent, EncodeTagged,
    EncodingOptions, Tagged, tag,
};
use tc_asn1_x500::Attribute;

/// The content's file name and media type, and whether they are covered by the
/// time stamp's hash.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MetaData {
    hash_protected: Asn1Boolean,
    file_name: Option<Asn1Utf8String>,
    media_type: Option<Asn1Ia5String>,
    other_meta_data: Option<Asn1SetOf<Attribute>>,
}

impl MetaData {
    /// Whether the metadata is hashed with the content, and nothing else.
    /// Variable time: branches only on the encoding structure.
    pub fn new(hash_protected: Asn1Boolean) -> Self {
        Self {
            hash_protected,
            file_name: None,
            media_type: None,
            other_meta_data: None,
        }
    }

    /// Adds the file name.
    /// Variable time: branches only on the encoding structure.
    pub fn with_file_name(mut self, file_name: Asn1Utf8String) -> Self {
        self.file_name = Some(file_name);
        self
    }

    /// Adds the MIME type.
    /// Variable time: branches only on the encoding structure.
    pub fn with_media_type(mut self, media_type: Asn1Ia5String) -> Self {
        self.media_type = Some(media_type);
        self
    }

    /// Sets other metadata.
    /// Variable time: branches only on the encoding structure.
    pub fn with_other_meta_data(mut self, other_meta_data: Vec<Attribute>) -> Self {
        self.other_meta_data = Some(Asn1SetOf::new(other_meta_data));
        self
    }

    /// Returns whether the metadata is covered by the time stamp's hash.
    /// Variable time: branches only on the encoding structure.
    pub fn hash_protected(&self) -> &Asn1Boolean {
        &self.hash_protected
    }

    /// Returns the file name, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn file_name(&self) -> Option<&Asn1Utf8String> {
        self.file_name.as_ref()
    }

    /// Returns the MIME type, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn media_type(&self) -> Option<&Asn1Ia5String> {
        self.media_type.as_ref()
    }

    /// Returns the other metadata in construction or wire order, if present.
    /// Variable time: branches only on the encoding structure.
    pub fn other_meta_data(&self) -> Option<&[Attribute]> {
        self.other_meta_data.as_ref().map(Asn1SetOf::members)
    }
}

impl DecodeContent for MetaData {
    /// Variable time: branches only on the encoding structure.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let mut fields = Children::from_contents(value, context)?;
        let hash_protected = fields.get()?;
        let file_name = fields.get_opt()?;
        let media_type = fields.get_opt()?;
        let other_meta_data = fields.get_opt()?;
        fields.end()?;
        let value = Self {
            hash_protected,
            file_name,
            media_type,
            other_meta_data,
        };
        Ok(value)
    }
}

impl DecodeInner for MetaData {
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

impl EncodeContent for MetaData {
    /// Variable time: branches only on the encoding structure.
    fn content_len(&self, rules: &EncodingOptions) -> usize {
        self.hash_protected.encoded_len(rules)
            + self.file_name.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self.media_type.as_ref().map_or(0, |v| v.encoded_len(rules))
            + self
                .other_meta_data
                .as_ref()
                .map_or(0, |v| v.encoded_len(rules))
    }

    /// Variable time: branches only on the encoding structure.
    fn encode_content(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = self.hash_protected.encode(rules, out)?;
        if let Some(v) = &self.file_name {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.media_type {
            at += v.encode(rules, &mut out[at..])?;
        }
        if let Some(v) = &self.other_meta_data {
            at += v.encode(rules, &mut out[at..])?;
        }
        Ok(at)
    }
}

impl Decode for MetaData {}

impl Tagged for MetaData {
    const TAG: &'static [u8] = tag::SEQUENCE;
}

impl EncodeTagged for MetaData {}

impl Encode for MetaData {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    /// Variable time: branches only on the encoding structure.
    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
