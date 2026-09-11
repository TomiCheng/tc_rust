//! ASN.1 `NumericString`：只接受數字與空白。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::NUMERIC_STRING as TAG;

/// 內容只含 ASCII 數字 `0`–`9` 與空白，因此可以直接借用為字串。
///
/// # Examples
///
/// 空白可用來分組，但正負號不屬於 NumericString 字集。
///
/// ```
/// use tc_asn1::{Asn1NumericString, Asn1Error};
///
/// let value = Asn1NumericString::new("012 3456789").unwrap();
/// assert_eq!(value.as_str(), "012 3456789");
/// assert_eq!(Asn1NumericString::new("+123"), Err(Asn1Error::MalformedValue));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1NumericString {
    text: String,
}

impl Asn1NumericString {
    /// 驗證字集並複製內容；不合法時回傳 [`Asn1Error::MalformedValue`]。
    /// 變動時間：依內容長度與遇到的字元決定掃描量。
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b' ')
        {
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

impl<'a> TryDecodeContent<'a> for Asn1NumericString {
    const TAG: &'static [u8] = TAG;

    /// 以建構時相同的字集規則驗證內容。
    /// 變動時間：依內容長度與字元分支。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Self::new(text)
    }
}

impl Encode for Asn1NumericString {
    /// 回傳 NumericString 的識別位元組。
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
    use crate::TryDecode;

    #[test]
    fn digits_and_spaces_round_trip_under_both_encoding_rules() {
        let text = "012 3456789";
        let value = Asn1NumericString::new(text).unwrap();
        for rules in [EncodingType::Ber, EncodingType::Der] {
            let mut out = [0; 13];
            assert_eq!(value.encode(rules, &mut out), Ok(out.len()));
            assert_eq!(&out[..2], &[0x12, 11]);
            assert_eq!(&out[2..], text.as_bytes());
            assert_eq!(value.content_len(rules), 11);
            let (used, decoded) = Asn1NumericString::try_decode(&out, Depth::DEFAULT).unwrap();
            assert_eq!(used, out.len());
            assert_eq!(decoded, value);
            assert_eq!(decoded.as_str(), text);
        }
    }

    #[test]
    fn construction_and_decoding_reject_characters_outside_the_numeric_alphabet() {
        for text in ["+1", "-1", "a", "1\t2", "１２", "\0"] {
            assert_eq!(Asn1NumericString::new(text), Err(Asn1Error::MalformedValue));
            assert_eq!(
                Asn1NumericString::try_decode_content(text.as_bytes(), Depth::DEFAULT),
                Err(Asn1Error::MalformedValue)
            );
        }
        assert_eq!(
            Asn1NumericString::try_decode_content(&[0xFF], Depth::DEFAULT),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_numeric_string_is_valid_and_encodes_with_zero_length() {
        let value = Asn1NumericString::new("").unwrap();
        assert_eq!(value, Asn1NumericString::default());
        assert_eq!(value.as_str(), "");
        let mut out = [0; 2];
        assert_eq!(value.encode(EncodingType::Der, &mut out), Ok(2));
        assert_eq!(out, [0x12, 0]);
        assert_eq!(
            Asn1NumericString::try_decode(&out, Depth::DEFAULT),
            Ok((2, value))
        );
    }

    #[test]
    fn a_numeric_string_rejects_an_ia5_string_tag() {
        assert_eq!(
            Asn1NumericString::try_decode(&[0x16, 1, b'1'], Depth::DEFAULT),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
