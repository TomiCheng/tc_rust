//! ASN.1 `IA5String`：ITU-T T.50，也就是 7 位 ASCII，含控制字元。

use alloc::string::String;

use crate::DecodingContext;
use crate::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// 內容保證全是 ASCII，所以 `as_str` 不會失敗。
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1Ia5String {
    text: String,
}

impl Asn1Ia5String {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::IA5_STRING;

    /// Universal constructed identifier for segmented encodings.
    pub const CONSTRUCTED_TAG: &'static [u8] = super::tag::CONSTRUCTED_IA5_STRING;

    /// 含非 ASCII 字元就拒絕。
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

impl<'a> crate::DecodeInner<'a> for Asn1Ia5String {
    fn decode_inner(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        let value = if element.is_constructed() {
            <Self as crate::DecodeConstructed<'a>>::decode_constructed(element.value(), context)?
        } else {
            <Self as crate::DecodeContent<'a>>::decode_content(element.value(), context)?
        };
        Ok((element.total_len(), value))
    }
    fn decode_inner_der(
        buff: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.is_constructed() {
            return Err(crate::Asn1Error::NotDer);
        }
        let value = if element.is_constructed() {
            <Self as crate::DecodeConstructed<'a>>::decode_constructed(element.value(), context)?
        } else {
            <Self as crate::DecodeContent<'a>>::decode_content_der(element.value(), context)?
        };
        Ok((element.total_len(), value))
    }
}
impl<'a> crate::Decode<'a> for Asn1Ia5String {
    fn decode(
        buff: &'a [u8],
        options: &crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        <Self as crate::DecodeInner<'a>>::decode_inner(
            buff,
            &mut crate::DecodingContext::new(options),
        )
    }
}

impl<'a> DecodeContent<'a> for Asn1Ia5String {
    fn decode_content(
        value: &'a [u8],
        context: &mut DecodingContext<'_>,
    ) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        if !value.is_ascii() {
            return Err(Asn1Error::MalformedValue);
        }
        // ASCII 是 UTF-8 的子集，上面驗過所以這裡不會失敗。
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }

    fn decode_content_der(
        value: &'a [u8],
        context: &mut crate::DecodingContext<'_>,
    ) -> Result<Self, crate::Asn1Error> {
        crate::decoding::decode_der_content::<Self>(value, context)
    }
}

crate::segments::constructed_string_decode!(Asn1Ia5String);

impl Asn1Ia5String {
    fn primitive_content_len(&self, _: &EncodingOptions) -> usize {
        self.text.len()
    }

    fn encode_primitive_content(
        &self,
        _: &EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        out[..self.text.len()].copy_from_slice(self.text.as_bytes());
        Ok(self.text.len())
    }
}

impl crate::EncodeContent for Asn1Ia5String {
    crate::segments::cer_string_content_encode!();
}

impl crate::EncodeTagged for Asn1Ia5String {
    crate::segments::cer_string_encode!();
}

impl Encode for Asn1Ia5String {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DecodingOptions;
    use crate::EncodingType;
    use crate::traits::Decode;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT.get(), 16 * 1024 * 1024, 65_536);

    #[test]
    fn ascii_text_round_trips() {
        let input = [0x16, 0x05, b'a', b'@', b'b', b'.', b'c'];
        let (used, s) = Asn1Ia5String::decode(&input, &OPTIONS).unwrap();
        assert_eq!(used, 7);
        assert_eq!(s.as_str(), "a@b.c");

        let mut out = [0_u8; 8];
        let written = s
            .encode(&EncodingOptions::new(EncodingType::Der), &mut out)
            .unwrap();
        assert_eq!(&out[..written], &input);
    }

    #[test]
    fn control_characters_are_part_of_ia5() {
        assert!(
            Asn1Ia5String::new(
                "a	b
"
            )
            .is_ok()
        );
        assert!(
            Asn1Ia5String::decode_content(&[0x00, 0x7F], &mut DecodingContext::new(&OPTIONS))
                .is_ok()
        );
    }

    #[test]
    fn anything_above_seven_bits_is_rejected() {
        assert_eq!(Asn1Ia5String::new("café"), Err(Asn1Error::MalformedValue));
        assert_eq!(
            Asn1Ia5String::decode_content(&[0x61, 0x80], &mut DecodingContext::new(&OPTIONS)),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_string_is_valid() {
        let (used, s) = Asn1Ia5String::decode(&[0x16, 0x00], &OPTIONS).unwrap();
        assert_eq!(used, 2);
        assert_eq!(s.as_str(), "");
    }
}
