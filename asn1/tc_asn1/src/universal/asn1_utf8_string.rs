//! ASN.1 `UTF8String`。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

use super::tag::UTF8_STRING as TAG;

/// Rust 的 `String` 本來就是合法 UTF-8，建構不會失敗；只有解碼要驗。
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1Utf8String {
    text: String,
}

impl Asn1Utf8String {
    pub fn new(text: &str) -> Self {
        Self {
            text: String::from(text),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl From<String> for Asn1Utf8String {
    fn from(text: String) -> Self {
        Self { text }
    }
}

impl<'a> DecodeContent<'a> for Asn1Utf8String {
    const TAG: &'static [u8] = TAG;
    const CONSTRUCTED: Option<fn(&'a [u8], Depth) -> Result<Self, Asn1Error>> =
        Some(<Self as crate::DecodeConstructed<'a>>::try_decode_constructed);

    /// 不合法的 UTF-8（含過長編碼、代理對）一律拒絕，這是 `from_utf8` 的規則。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self::new(text))
    }
}

crate::segments::constructed_string_decode!(Asn1Utf8String);

impl Encode for Asn1Utf8String {
    crate::segments::cer_string_encode!();
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingOptions) -> usize {
        self.text.len()
    }
    fn encode_content(&self, _: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
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
    fn cer_utf8_segments_are_octet_strings_and_may_split_a_character() {
        let text = alloc::format!("{}é", "a".repeat(999));
        let value = Asn1Utf8String::new(&text);
        let mut expected = alloc::vec![0x2c, 0x80, 4, 0x82, 3, 0xe8];
        expected.extend_from_slice(&[b'a'; 999]);
        expected.extend_from_slice(&[0xc3, 4, 1, 0xa9, 0, 0]);
        assert_eq!(value.encode_to_vec(EncodingOptions::Cer).unwrap(), expected);
        let tree = crate::Asn1Object::from(value.clone());
        assert_eq!(tree.encode_to_vec(EncodingOptions::Cer).unwrap(), expected);
        assert_eq!(
            Asn1Utf8String::try_decode_exact(&expected, DEPTH),
            Ok(value.clone())
        );
        assert_eq!(
            crate::Asn1Object::try_decode_exact(&expected, DEPTH),
            Ok(tree)
        );
        let mut definite = alloc::vec![0x0c, 0x82, 3, 0xe9];
        definite.extend_from_slice(text.as_bytes());
        for rules in [
            EncodingOptions::Ber(crate::LengthForm::Definite),
            EncodingOptions::Der,
        ] {
            assert_eq!(value.encode_to_vec(rules).unwrap(), definite);
        }
    }

    #[test]
    fn constructed_utf8_validates_after_joining_and_rejects_wrong_segment_tags() {
        for input in [
            &[0x2c, 4, 4, 2, 0xc3, 0xa9][..],
            &[0x2c, 6, 4, 1, 0xc3, 4, 1, 0xa9],
            &[0x2c, 8, 0x24, 3, 4, 1, 0xc3, 4, 1, 0xa9],
        ] {
            assert_eq!(
                Asn1Utf8String::try_decode_exact(input, DEPTH)
                    .unwrap()
                    .as_str(),
                "é"
            );
        }
        assert_eq!(
            Asn1Utf8String::try_decode_exact(&[0x2c, 3, 4, 1, 0xc3], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            Asn1Utf8String::try_decode_exact(&[0x2c, 3, 0x0c, 1, b'A'], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
        let tree = crate::Asn1Object::try_decode_exact(&[0x2c, 3, 4, 1, b'A'], DEPTH).unwrap();
        assert_eq!(tree, crate::Asn1Object::from(Asn1Utf8String::new("A")));
        assert_eq!(
            alloc::string::ToString::to_string(&tree),
            "UTF8String \"A\"\n"
        );
    }

    #[test]
    fn multibyte_text_round_trips() {
        let text = "café 台北";
        let s = Asn1Utf8String::new(text);
        assert_eq!(
            s.content_len(EncodingOptions::Der),
            text.len(),
            "位元組數不是字元數"
        );

        let mut out = [0_u8; 32];
        let written = s.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(out[0], 0x0C);

        let (used, decoded) = Asn1Utf8String::try_decode(&out[..written], DEPTH).unwrap();
        assert_eq!(used, written);
        assert_eq!(decoded.as_str(), text);
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        for bytes in [
            &[0xFF][..],
            &[0xC0, 0x80],
            &[0xED, 0xA0, 0x80],
            &[0xE4, 0xB8],
        ] {
            assert_eq!(
                Asn1Utf8String::try_decode_content(bytes, DEPTH),
                Err(Asn1Error::MalformedValue),
                "{bytes:02X?}"
            );
        }
    }

    #[test]
    fn an_empty_string_is_valid() {
        let (used, s) = Asn1Utf8String::try_decode(&[0x0C, 0x00], DEPTH).unwrap();
        assert_eq!(used, 2);
        assert_eq!(s.as_str(), "");
    }
}
