//! ASN.1 `BMPString`：UCS-2 大端序，不接受代理碼或代理對。

use alloc::string::String;

use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

/// 以 Rust 字串持有 BMP 字元，線路上每個字元使用兩個大端序位元組。
///
/// UCS-2 不是 UTF-16：非 BMP 字元不能改用代理對表示。
/// 建構時就拒絕超過 `U+FFFF` 的字元，因此編碼不會截斷它們。
///
/// # Examples
///
/// BMP 的中文字元可編碼，emoji 則必須使用其他字串型別。
///
/// ```
/// use tc_asn1::{Asn1BmpString, Asn1Error, Encode, EncodingOptions};
///
/// let value = Asn1BmpString::new("台北").unwrap();
/// let mut out = [0; 6];
/// value.encode(EncodingOptions::Der, &mut out).unwrap();
/// assert_eq!(out, [0x1E, 4, 0x53, 0xF0, 0x53, 0x17]);
/// assert_eq!(Asn1BmpString::new("😀"), Err(Asn1Error::MalformedValue));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1BmpString {
    text: String,
}

impl Asn1BmpString {
    /// Universal identifier octets for this type's default encoding form.
    pub const TAG: &'static [u8] = super::tag::BMP_STRING;

    /// Universal constructed identifier for segmented encodings.
    pub const CONSTRUCTED_TAG: &'static [u8] = super::tag::CONSTRUCTED_BMP_STRING;

    /// 驗證每個字元都在 BMP 內，否則回傳 [`Asn1Error::MalformedValue`]。
    /// 變動時間：依字元數與遇到的字元決定掃描量。
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if text.chars().any(|ch| u32::from(ch) > 0xFFFF) {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(Self {
            text: String::from(text),
        })
    }

    /// 借用已驗證的字串。
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<'a> crate::Decode<'a> for Asn1BmpString {
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

impl<'a> DecodeContent<'a> for Asn1BmpString {
    /// 逐個解讀兩位元組的 UCS-2 碼位；奇數長度與所有代理碼一律拒絕。
    /// 變動時間：依內容長度與碼位分支，不嘗試合併代理對。
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
        let (units, remainder) = value.as_chunks::<2>();
        if !remainder.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut text = String::new();
        for bytes in units {
            let unit = u16::from_be_bytes(*bytes);
            let ch = char::from_u32(u32::from(unit)).ok_or(Asn1Error::MalformedValue)?;
            text.push(ch);
        }
        Ok(Self { text })
    }
}

crate::segments::constructed_string_decode!(Asn1BmpString);

impl Asn1BmpString {
    /// 內容長度是字元數的兩倍。變動時間：需要走訪字串計算字元數。
    fn primitive_content_len(&self, _: EncodingOptions) -> usize {
        self.text.chars().count() * 2
    }

    /// 每個字元寫成 UCS-2 大端序。變動時間：依字串長度走訪字元。
    fn encode_primitive_content(
        &self,
        _: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        let mut at = 0;
        for ch in self.text.chars() {
            // 建構與解碼已保證碼位不超過 U+FFFF。
            out[at..at + 2].copy_from_slice(&(ch as u16).to_be_bytes());
            at += 2;
        }
        Ok(at)
    }
}

impl crate::EncodeContent for Asn1BmpString {
    crate::segments::cer_string_content_encode!();
}

impl crate::EncodeTagged for Asn1BmpString {
    crate::segments::cer_string_encode!();
}

impl Encode for Asn1BmpString {
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
    use crate::Decode;
    use crate::EncodeContent;

    #[test]
    fn latin_and_chinese_text_round_trip_as_two_bytes_per_character() {
        for (text, contents) in [
            ("café", &[0, b'c', 0, b'a', 0, b'f', 0, 0xE9][..]),
            ("台北", &[0x53, 0xF0, 0x53, 0x17]),
        ] {
            let original = Asn1BmpString::new(text).unwrap();
            for rules in [
                EncodingOptions::Ber(crate::LengthForm::Definite),
                EncodingOptions::Der,
            ] {
                let mut out = [0; 16];
                let written = original.encode(rules, &mut out).unwrap();
                assert_eq!(&out[..2], &[0x1E, contents.len() as u8]);
                assert_eq!(&out[2..written], contents);
                assert_eq!(original.content_len(rules), 2 * text.chars().count());
                assert_eq!(written, original.encoded_len(rules));
                let (used, decoded) =
                    Asn1BmpString::try_decode(&out[..written], DecodingOptions::default()).unwrap();
                assert_eq!(used, written);
                assert_eq!(decoded, original);
                assert_eq!(decoded.as_str(), text);
            }
        }
    }

    #[test]
    fn an_odd_number_of_content_bytes_is_rejected() {
        for value in [&[0][..], &[0, b'A', 0]] {
            assert_eq!(
                Asn1BmpString::try_decode_content(value, DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn isolated_surrogates_and_valid_utf16_surrogate_pairs_are_rejected() {
        for value in [
            &[0xD8, 0][..],
            &[0xDB, 0xFF],
            &[0xDC, 0],
            &[0xDF, 0xFF],
            &[0xD8, 0x3D, 0xDE, 0],
        ] {
            assert_eq!(
                Asn1BmpString::try_decode_content(value, DecodingOptions::default()),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn construction_rejects_emoji_and_the_first_code_point_outside_the_bmp() {
        for text in ["😀", "\u{10000}"] {
            assert_eq!(Asn1BmpString::new(text), Err(Asn1Error::MalformedValue));
        }
    }

    #[test]
    fn valid_bmp_boundaries_survive_encoding_and_decoding() {
        let text = "\0\u{D7FF}\u{E000}\u{FFFF}";
        let original = Asn1BmpString::new(text).unwrap();
        let mut out = [0; 10];
        assert_eq!(original.encode(EncodingOptions::Der, &mut out), Ok(10));
        assert_eq!(out, [0x1E, 8, 0, 0, 0xD7, 0xFF, 0xE0, 0, 0xFF, 0xFF]);
        assert_eq!(
            Asn1BmpString::try_decode(&out, DecodingOptions::default()),
            Ok((10, original))
        );
    }

    #[test]
    fn an_empty_bmp_string_is_valid_and_encodes_with_zero_length() {
        let original = Asn1BmpString::new("").unwrap();
        assert_eq!(original, Asn1BmpString::default());
        let mut out = [0; 2];
        assert_eq!(original.encode(EncodingOptions::Der, &mut out), Ok(2));
        assert_eq!(out, [0x1E, 0]);
        assert_eq!(
            Asn1BmpString::try_decode(&out, DecodingOptions::default()),
            Ok((2, original))
        );
    }

    #[test]
    fn the_schema_checks_tags_a_bmp_string_rejects_a_utf8_string_tag() {
        assert_eq!(
            crate::Fields::new(&[0x0C, 0], DecodingOptions::default())
                .and_then(|mut fields| fields.required::<Asn1BmpString>(Asn1BmpString::TAG)),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
