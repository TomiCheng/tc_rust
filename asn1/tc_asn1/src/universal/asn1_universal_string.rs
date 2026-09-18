//! ASN.1 `UniversalString`: UCS-4 big-endian, four octets per Unicode scalar value.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Holds Unicode scalar values as a Rust string; on the wire each is four
/// big-endian octets. A Rust string already excludes surrogates and values
/// above `U+10FFFF`, so building never fails; decoding validates each code
/// point. Characters outside the BMP take a single code point, no surrogates.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1UniversalString {
    text: String,
}

impl Asn1UniversalString {
    pub const TAG: &'static [u8] = super::tag::UNIVERSAL_STRING;

    pub fn new(text: &str) -> Self {
        Self {
            text: String::from(text),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Four octets per character.
    fn wire_len(&self) -> usize {
        self.text.chars().count() * 4
    }
}

impl From<String> for Asn1UniversalString {
    fn from(text: String) -> Self {
        Self { text }
    }
}

impl core::fmt::Display for Asn1UniversalString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1UniversalString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1UniversalStringConstructed.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1UniversalString {}
impl Tagged for Asn1UniversalString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1UniversalString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let (units, remainder) = value.as_chunks::<4>();
        if !remainder.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut text = String::with_capacity(units.len());
        for bytes in units {
            let ch = char::from_u32(u32::from_be_bytes(*bytes)).ok_or(Asn1Error::MalformedValue)?;
            text.push(ch);
        }
        Ok(Self { text })
    }
}

impl EncodeContent for Asn1UniversalString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.wire_len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.wire_len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        for (slot, ch) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.text.chars()) {
            *slot = u32::from(ch).to_be_bytes();
        }
        Ok(out.len())
    }
}

impl EncodeTagged for Asn1UniversalString {
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(self.wire_len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1UniversalString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
