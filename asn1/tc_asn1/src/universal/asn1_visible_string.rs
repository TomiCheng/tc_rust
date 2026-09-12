//! ASN.1 `VisibleString`：只接受可列印 ASCII，包含空白。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

use super::tag::VISIBLE_STRING as TAG;

/// 內容保證位於 `0x20`–`0x7E`，不接受控制字元或非 ASCII 字元。
///
/// # Examples
///
/// 空白與標點可以使用，但換行不在字集中。
///
/// ```
/// use tc_asn1::{Asn1VisibleString, Asn1Error};
///
/// let value = Asn1VisibleString::new("Room 42 ~ open").unwrap();
/// assert_eq!(value.as_str(), "Room 42 ~ open");
/// assert_eq!(Asn1VisibleString::new("Room 42\n"), Err(Asn1Error::MalformedValue));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1VisibleString {
    text: String,
}

impl Asn1VisibleString {
    /// 驗證字集並複製內容；不合法時回傳 [`Asn1Error::MalformedValue`]。
    /// 變動時間：依內容長度與遇到的字元決定掃描量。
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text.bytes().all(|byte| (0x20..=0x7E).contains(&byte)) {
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

impl<'a> DecodeContent<'a> for Asn1VisibleString {
    const TAG: &'static [u8] = TAG;

    /// 以建構時相同的字集規則驗證內容。
    /// 變動時間：依內容長度與字元分支。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Self::new(text)
    }
}

impl Encode for Asn1VisibleString {
    /// 回傳 VisibleString 的識別位元組。
    fn tag(&self) -> &[u8] {
        TAG
    }

    /// 回傳內容長度。常數時間：讀取已儲存的字串長度。
    fn content_len(&self, _: EncodingType) -> usize {
        self.text.len()
    }

    /// 原樣寫入已驗證的內容。變動時間：複製量由內容長度決定。
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.text.len()].copy_from_slice(self.text.as_bytes());
        Ok(self.text.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode;

    #[test]
    fn printable_ascii_round_trips_under_both_encoding_rules() {
        let value = Asn1VisibleString::new("A 9~").unwrap();
        for rules in [EncodingType::Ber, EncodingType::Der] {
            let mut out = [0; 6];
            assert_eq!(value.encode(rules, &mut out), Ok(out.len()));
            assert_eq!(out, [0x1A, 4, b'A', b' ', b'9', b'~']);
            assert_eq!(value.content_len(rules), 4);
            let (used, decoded) = Asn1VisibleString::try_decode(&out, Depth::DEFAULT).unwrap();
            assert_eq!(used, out.len());
            assert_eq!(decoded, value);
            assert_eq!(decoded.as_str(), "A 9~");
        }
    }

    #[test]
    fn visible_string_boundaries_accept_space_and_tilde_but_reject_adjacent_controls() {
        for (text, accepted) in [("\x1F", false), (" ", true), ("~", true), ("\x7F", false)] {
            assert_eq!(Asn1VisibleString::new(text).is_ok(), accepted);
            assert_eq!(
                Asn1VisibleString::try_decode_content(text.as_bytes(), Depth::DEFAULT).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn construction_and_decoding_reject_non_ascii_and_control_characters() {
        for text in ["台北", "café", "a\nb", "\0"] {
            assert_eq!(Asn1VisibleString::new(text), Err(Asn1Error::MalformedValue));
            assert_eq!(
                Asn1VisibleString::try_decode_content(text.as_bytes(), Depth::DEFAULT),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            Asn1VisibleString::try_decode_content(&[0x80], Depth::DEFAULT),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_visible_string_is_valid_and_encodes_with_zero_length() {
        let value = Asn1VisibleString::new("").unwrap();
        assert_eq!(value, Asn1VisibleString::default());
        assert_eq!(value.as_str(), "");
        let mut out = [0; 2];
        assert_eq!(value.encode(EncodingType::Der, &mut out), Ok(2));
        assert_eq!(out, [0x1A, 0]);
        assert_eq!(
            Asn1VisibleString::try_decode(&out, Depth::DEFAULT),
            Ok((2, value))
        );
    }

    #[test]
    fn a_visible_string_rejects_an_ia5_string_tag() {
        assert_eq!(
            Asn1VisibleString::try_decode(&[0x16, 1, b'A'], Depth::DEFAULT),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
