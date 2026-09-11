//! ASN.1 `UniversalString`：UCS-4 大端序，每個 Unicode 純量值四個位元組。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::UNIVERSAL_STRING as TAG;

/// 以 Rust 字串持有 Unicode 純量值，線路上使用 UCS-4 大端序。
///
/// Rust 字串已排除代理碼與超過 `U+10FFFF` 的值，所以建構不會失敗；
/// 解碼時則必須驗證每個四位元組碼位。非 BMP 字元也只佔一個碼位。
///
/// # Examples
///
/// emoji 可以直接以單一 UCS-4 碼位表示，不使用 UTF-16 代理對。
///
/// ```
/// use tc_asn1::{Asn1UniversalString, Depth, Encode, EncodingType, TryDecode};
///
/// let value = Asn1UniversalString::new("😀");
/// let mut out = [0; 6];
/// value.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, [0x1C, 4, 0, 1, 0xF6, 0]);
/// let (_, decoded) = Asn1UniversalString::try_decode(&out, Depth::DEFAULT).unwrap();
/// assert_eq!(decoded.as_str(), "😀");
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1UniversalString {
    text: String,
}

impl Asn1UniversalString {
    /// 複製合法的 Rust 字串。變動時間：配置與複製量由字串長度決定。
    pub fn new(text: &str) -> Self {
        Self {
            text: String::from(text),
        }
    }

    /// 借用字串。
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl From<String> for Asn1UniversalString {
    /// 接收擁有的字串，不再配置或複製。
    fn from(text: String) -> Self {
        Self { text }
    }
}

impl<'a> TryDecodeContent<'a> for Asn1UniversalString {
    const TAG: &'static [u8] = TAG;

    /// 解讀 UCS-4 大端序；長度不是四的倍數或碼位不是 Unicode 純量值時拒絕。
    /// 變動時間：依內容長度與碼位分支。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let (units, remainder) = value.as_chunks::<4>();
        if !remainder.is_empty() {
            return Err(Asn1Error::MalformedValue);
        }
        let mut text = String::new();
        for bytes in units {
            let unit = u32::from_be_bytes(*bytes);
            let ch = char::from_u32(unit).ok_or(Asn1Error::MalformedValue)?;
            text.push(ch);
        }
        Ok(Self { text })
    }
}

impl Encode for Asn1UniversalString {
    /// 回傳 UniversalString 的識別位元組。
    fn tag(&self) -> &[u8] {
        TAG
    }

    /// 內容長度是字元數的四倍。變動時間：需要走訪字串計算字元數。
    fn content_len(&self, _: EncodingType) -> usize {
        self.text.chars().count() * 4
    }

    /// 每個字元寫成 UCS-4 大端序。變動時間：依字串長度走訪字元。
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let mut at = 0;
        for ch in self.text.chars() {
            out[at..at + 4].copy_from_slice(&u32::from(ch).to_be_bytes());
            at += 4;
        }
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TryDecode;

    #[test]
    fn latin_chinese_and_emoji_text_round_trip_as_four_bytes_per_character() {
        for (text, contents) in [
            (
                "café",
                &[0, 0, 0, b'c', 0, 0, 0, b'a', 0, 0, 0, b'f', 0, 0, 0, 0xE9][..],
            ),
            ("台北", &[0, 0, 0x53, 0xF0, 0, 0, 0x53, 0x17]),
            ("😀", &[0, 1, 0xF6, 0]),
        ] {
            let original = Asn1UniversalString::new(text);
            assert_eq!(original, Asn1UniversalString::from(String::from(text)));
            for rules in [EncodingType::Ber, EncodingType::Der] {
                let mut out = [0; 24];
                let written = original.encode(rules, &mut out).unwrap();
                assert_eq!(&out[..2], &[0x1C, contents.len() as u8]);
                assert_eq!(&out[2..written], contents);
                assert_eq!(original.content_len(rules), 4 * text.chars().count());
                assert_eq!(written, original.encoded_len(rules));
                let (used, decoded) =
                    Asn1UniversalString::try_decode(&out[..written], Depth::DEFAULT).unwrap();
                assert_eq!(used, written);
                assert_eq!(decoded, original);
                assert_eq!(decoded.as_str(), text);
            }
        }
    }

    #[test]
    fn content_lengths_that_are_not_multiples_of_four_are_rejected() {
        for length in [1, 2, 3, 5, 6, 7] {
            assert_eq!(
                Asn1UniversalString::try_decode_content(&[0; 7][..length], Depth::DEFAULT),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn surrogate_code_points_are_rejected_including_both_range_boundaries() {
        for unit in [0xD800_u32, 0xDBFF, 0xDC00, 0xDFFF] {
            assert_eq!(
                Asn1UniversalString::try_decode_content(&unit.to_be_bytes(), Depth::DEFAULT),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn code_points_above_the_unicode_maximum_are_rejected() {
        for unit in [0x110000_u32, u32::MAX] {
            assert_eq!(
                Asn1UniversalString::try_decode_content(&unit.to_be_bytes(), Depth::DEFAULT),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn valid_unicode_boundaries_survive_encoding_and_decoding() {
        let text = "\0\u{D7FF}\u{E000}\u{FFFF}\u{10000}\u{10FFFF}";
        let original = Asn1UniversalString::new(text);
        let mut out = [0; 26];
        assert_eq!(original.encode(EncodingType::Der, &mut out), Ok(26));
        assert_eq!(&out[22..], &[0, 0x10, 0xFF, 0xFF]);
        assert_eq!(
            Asn1UniversalString::try_decode(&out, Depth::DEFAULT),
            Ok((26, original))
        );
    }

    #[test]
    fn an_empty_universal_string_is_valid_and_encodes_with_zero_length() {
        let original = Asn1UniversalString::new("");
        assert_eq!(original, Asn1UniversalString::default());
        let mut out = [0; 2];
        assert_eq!(original.encode(EncodingType::Der, &mut out), Ok(2));
        assert_eq!(out, [0x1C, 0]);
        assert_eq!(
            Asn1UniversalString::try_decode(&out, Depth::DEFAULT),
            Ok((2, original))
        );
    }

    #[test]
    fn a_universal_string_rejects_a_bmp_string_tag() {
        assert_eq!(
            Asn1UniversalString::try_decode(&[0x1E, 0], Depth::DEFAULT),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
