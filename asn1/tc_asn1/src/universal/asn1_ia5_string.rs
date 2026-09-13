//! ASN.1 `IA5String`：ITU-T T.50，也就是 7 位 ASCII，含控制字元。

use alloc::string::String;

use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
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

impl<'a> crate::Decode<'a> for Asn1Ia5String {
    fn try_decode(
        buff: &'a [u8],
        options: crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, options)?;
        let value = if element.is_constructed() {
            <Self as crate::DecodeConstructed<'a>>::try_decode_constructed(
                element.value(),
                options,
            )?
        } else {
            <Self as crate::DecodeContent<'a>>::try_decode_content(element.value(), options)?
        };
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for Asn1Ia5String {
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
        if !value.is_ascii() {
            return Err(Asn1Error::MalformedValue);
        }
        // ASCII 是 UTF-8 的子集，上面驗過所以這裡不會失敗。
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }
}

crate::segments::constructed_string_decode!(Asn1Ia5String);

impl Asn1Ia5String {
    fn primitive_content_len(&self, _: EncodingOptions) -> usize {
        self.text.len()
    }

    fn encode_primitive_content(
        &self,
        _: EncodingOptions,
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
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decode;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn ascii_text_round_trips() {
        let input = [0x16, 0x05, b'a', b'@', b'b', b'.', b'c'];
        let (used, s) = Asn1Ia5String::try_decode(&input, OPTIONS).unwrap();
        assert_eq!(used, 7);
        assert_eq!(s.as_str(), "a@b.c");

        let mut out = [0_u8; 8];
        let written = s.encode(EncodingOptions::Der, &mut out).unwrap();
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
        assert!(Asn1Ia5String::try_decode_content(&[0x00, 0x7F], OPTIONS).is_ok());
    }

    #[test]
    fn anything_above_seven_bits_is_rejected() {
        assert_eq!(Asn1Ia5String::new("café"), Err(Asn1Error::MalformedValue));
        assert_eq!(
            Asn1Ia5String::try_decode_content(&[0x61, 0x80], OPTIONS),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_string_is_valid() {
        let (used, s) = Asn1Ia5String::try_decode(&[0x16, 0x00], OPTIONS).unwrap();
        assert_eq!(used, 2);
        assert_eq!(s.as_str(), "");
    }
}
