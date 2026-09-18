use alloc::string::String;

use super::cer_common::too_long_for_cer;
use crate::traits::encode::default_encode;
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodeContent,
    EncodeTagged, EncodingOptions, Tagged,
};

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Asn1Ia5String {
    text: String,
}

impl Asn1Ia5String {
    pub const TAG: &'static [u8] = super::tag::IA5_STRING;

    /// Rejects any non-ASCII character.
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text.is_ascii() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl core::fmt::Display for Asn1Ia5String {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}

impl DecodeInner for Asn1Ia5String {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        // Only the primitive form; the constructed form (36) is read through
        // Asn1OctetStringConstructed and validated after joining.
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Ia5String {}
impl Tagged for Asn1Ia5String {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Ia5String {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if !value.is_ascii() {
            return Err(Asn1Error::MalformedValue);
        }
        // ASCII is a subset of UTF-8, so this cannot fail after the check above.
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }
}

impl EncodeContent for Asn1Ia5String {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.text.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.text.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(self.text.as_bytes());
        Ok(self.text.len())
    }
}

impl EncodeTagged for Asn1Ia5String {
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if too_long_for_cer(self.text.len(), rules) {
            return Err(Asn1Error::PrimitiveTooLong);
        }
        default_encode(self, tag, rules, out)
    }
}

impl Encode for Asn1Ia5String {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}
