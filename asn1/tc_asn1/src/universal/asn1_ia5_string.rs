//! ASN.1 `IA5String`：ITU-T T.50，也就是 7 位 ASCII，含控制字元。

use alloc::string::String;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::IA5_STRING as TAG;

/// 內容保證全是 ASCII，所以 `as_str` 不會失敗。
#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Asn1Ia5String {
    text: String,
}

impl Asn1Ia5String {
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

impl<'a> TryDecodeContent<'a> for Asn1Ia5String {
    const TAG: &'static [u8] = TAG;

    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
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

impl Encode for Asn1Ia5String {
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
    fn ascii_text_round_trips() {
        let input = [0x16, 0x05, b'a', b'@', b'b', b'.', b'c'];
        let (used, s) = Asn1Ia5String::try_decode(&input, DEPTH).unwrap();
        assert_eq!(used, 7);
        assert_eq!(s.as_str(), "a@b.c");

        let mut out = [0_u8; 8];
        let written = s.encode(EncodingType::Der, &mut out).unwrap();
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
        assert!(Asn1Ia5String::try_decode_content(&[0x00, 0x7F], DEPTH).is_ok());
    }

    #[test]
    fn anything_above_seven_bits_is_rejected() {
        assert_eq!(Asn1Ia5String::new("café"), Err(Asn1Error::MalformedValue));
        assert_eq!(
            Asn1Ia5String::try_decode_content(&[0x61, 0x80], DEPTH),
            Err(Asn1Error::MalformedValue)
        );
    }

    #[test]
    fn an_empty_string_is_valid() {
        let (used, s) = Asn1Ia5String::try_decode(&[0x16, 0x00], DEPTH).unwrap();
        assert_eq!(used, 2);
        assert_eq!(s.as_str(), "");
    }
}
