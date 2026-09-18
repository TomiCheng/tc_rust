//! ASN.1 `BMPString`: UCS-2 big-endian; surrogate code points and pairs are rejected.

use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

/// Holds BMP characters as a Rust string; on the wire each character is two
/// big-endian octets.
///
/// UCS-2 is not UTF-16: characters outside the BMP cannot be written as
/// surrogate pairs, so `new` rejects anything above `U+FFFF`.
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1BmpString {
    text: String,
}

impl Asn1BmpString {
    pub const TAG: &'static [u8] = super::tag::BMP_STRING;

    /// Rejects any character above `U+FFFF`.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if text.chars().any(|ch| u32::from(ch) > 0xFFFF) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Two octets per character.
    fn wire_len(&self) -> usize {
        self.text.chars().count() * 2
    }
}

impl core::fmt::Display for Asn1BmpString {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1BmpString {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form is Asn1BmpStringConstructed.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1BmpString {}
impl Tagged for Asn1BmpString {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1BmpString {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        let (units, remainder) = value.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut text = String::with_capacity(units.len());
        for bytes in units {
            let unit = u16::from_be_bytes(*bytes);
            // from_u32 rejects D800-DFFF, which UCS-2 must not contain.
            let ch = char::from_u32(u32::from(unit)).ok_or(Asn1Error::MalformedValue)?;
            text.push(ch);
        }
        Ok(Self { text })
    }
}

impl EncodeContent for Asn1BmpString {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.wire_len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.wire_len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        for (slot, ch) in out.as_chunks_mut::<2>().0.iter_mut().zip(self.text.chars()) {
            // new and decode_content guarantee the code point fits in u16.
            *slot = (ch as u16).to_be_bytes();
        }
        Ok(out.len())
    }
}

impl EncodeTagged for Asn1BmpString {
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

impl Encode for Asn1BmpString {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
