use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodingOptions,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Boolean(bool);

impl Asn1Boolean {
    pub const TAG: &'static [u8] = super::tag::BOOLEAN;

    pub const fn is_true(&self) -> bool {
        self.0
    }

    pub const fn is_false(&self) -> bool {
        !self.0
    }
}

impl From<bool> for Asn1Boolean {
    fn from(value: bool) -> Self {
        Self(value)
    }
}

impl core::fmt::Display for Asn1Boolean {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl DecodeInner for Asn1Boolean {
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
impl Decode for Asn1Boolean {
    fn decode(
        buff: &[u8],
        options: &DecodingOptions,
    ) -> Result<(usize, Self), Asn1Error> {
        let mut context = DecodingContext::new(options.clone());
        Self::decode_inner(buff, &mut context)
    }
}
impl DecodeContent for Asn1Boolean {
    fn decode_content(
        value: &[u8],
        context: &mut DecodingContext,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        match value {
            // Accept BER truth values; re-encoding normalizes nonzero octets to FF.
            [octet] => Ok(Asn1Boolean(*octet != 0)),
            _ => Err(Asn1Error::MalformedValue),
        }
    }

    fn decode_content_der(
        value: &[u8],
        _context: &mut DecodingContext,
    ) -> Result<Self, Asn1Error> {
        // X.690 §11.1: DER writes TRUE as FF and FALSE as 00; nothing else.
        match value {
            [0x00] => Ok(Asn1Boolean(false)),
            [0xFF] => Ok(Asn1Boolean(true)),
            [_] => Err(Asn1Error::NotDer),
            _ => Err(Asn1Error::MalformedValue),
        }
    }
}

impl crate::EncodeContent for Asn1Boolean {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        1
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let octet = out.first_mut().ok_or(Asn1Error::BufferTooSmall)?;
        *octet = u8::from(self.0).wrapping_neg();
        Ok(1)
    }
}

impl crate::EncodeTagged for Asn1Boolean {}

impl Encode for Asn1Boolean {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}