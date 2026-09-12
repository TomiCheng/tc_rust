//! ASN.1 `PrintableString`。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

use super::tag::PRINTABLE_STRING as TAG;

/// X.680 41.4 的字元集：英數、空白，以及 `' ( ) + , - . / : = ?`。
///
/// 注意**沒有** `@`、`&`、`*`、`_`，所以 email 不能放這裡（要用 IA5String）。
fn is_printable(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b' ' | 0x27 | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1PrintableString {
    text: String,
}

impl Asn1PrintableString {
    pub fn new(text: &str) -> Result<Self, Asn1Error> {
        if !text.bytes().all(is_printable) {
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

impl<'a> DecodeContent<'a> for Asn1PrintableString {
    const TAG: &'static [u8] = TAG;

    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        if !value.iter().all(|b| is_printable(*b)) {
            return Err(Asn1Error::MalformedValue);
        }
        // 字元集是 ASCII 的子集，所以是合法 UTF-8。
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self {
            text: String::from(text),
        })
    }
}

impl Encode for Asn1PrintableString {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingType) -> usize {
        self.text.len()
    }
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.text.len()].copy_from_slice(self.text.as_bytes());
        Ok(self.text.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decode;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn the_whole_permitted_set_is_accepted() {
        let all = "ABCxyz019 '()+,-./:=?";
        let s = Asn1PrintableString::new(all).unwrap();
        assert_eq!(s.as_str(), all);
    }

    #[test]
    fn characters_outside_the_set_are_rejected() {
        for text in ["a@b", "a&b", "a*b", "a_b", "a	b", "café", "\""] {
            assert_eq!(
                Asn1PrintableString::new(text),
                Err(Asn1Error::MalformedValue),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_country_code_round_trips() {
        // C=TW 的值
        let input = [0x13, 0x02, b'T', b'W'];
        let (used, s) = Asn1PrintableString::try_decode(&input, DEPTH).unwrap();
        assert_eq!(used, 4);
        assert_eq!(s.as_str(), "TW");

        let mut out = [0_u8; 8];
        let written = s.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input);
    }
}
