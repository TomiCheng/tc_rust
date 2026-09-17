use core::fmt::{Display, Formatter};

use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodingOptions,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Asn1Null;

impl Asn1Null {
    pub const TAG: &'static [u8] = super::tag::NULL;
}

impl Display for Asn1Null {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("NULL")
    }
}

impl DecodeInner for Asn1Null {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }
    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}
impl Decode for Asn1Null {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl DecodeContent for Asn1Null {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if value.is_empty() {
            Ok(Asn1Null)
        } else {
            Err(Asn1Error::MalformedValue)
        }
    }

    fn decode_content_der(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        // The contents are always empty, so BER and DER agree.
        Self::decode_content(value, context)
    }
}

impl crate::EncodeContent for Asn1Null {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        0
    }

    fn encode_content(&self, _: &EncodingOptions, _: &mut [u8]) -> Result<usize, Asn1Error> {
        Ok(0)
    }
}

impl crate::EncodeTagged for Asn1Null {}

impl Encode for Asn1Null {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}
