//! ASN.1 `UTF8String`。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

const TAG: &[u8] = &[0x0C];

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

impl<'a> TryDecodeContent<'a> for Asn1Utf8String {
    const TAG: &'static [u8] = TAG;

    /// 不合法的 UTF-8（含過長編碼、代理對）一律拒絕，這是 `from_utf8` 的規則。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let text = core::str::from_utf8(value).map_err(|_| Asn1Error::MalformedValue)?;
        Ok(Self::new(text))
    }
}

impl Encode for Asn1Utf8String {
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
    use crate::traits::TryDecode;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn multibyte_text_round_trips() {
        let text = "café 台北";
        let s = Asn1Utf8String::new(text);
        assert_eq!(
            s.content_len(EncodingType::Der),
            text.len(),
            "位元組數不是字元數"
        );

        let mut out = [0_u8; 32];
        let written = s.encode(EncodingType::Der, &mut out).unwrap();
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
