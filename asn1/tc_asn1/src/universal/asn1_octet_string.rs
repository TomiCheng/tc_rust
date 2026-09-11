//! ASN.1 `OCTET STRING`。

use alloc::vec::Vec;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::OCTET_STRING as TAG;

/// 任意位元組，沒有解讀。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Asn1OctetString {
    bytes: Vec<u8>,
}

impl Asn1OctetString {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<Vec<u8>> for Asn1OctetString {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl<'a> TryDecodeContent<'a> for Asn1OctetString {
    const TAG: &'static [u8] = TAG;

    /// 任何內容都合法，包括空的。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        Ok(Self::new(value))
    }
}

impl Encode for Asn1OctetString {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingType) -> usize {
        self.bytes.len()
    }
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TryDecode;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn bytes_pass_through_untouched_in_both_directions() {
        let input = [0x04, 0x03, 0xDE, 0xAD, 0x00];
        let (used, s) = Asn1OctetString::try_decode(&input, DEPTH).unwrap();
        assert_eq!(used, 5);
        assert_eq!(s.as_bytes(), &[0xDE, 0xAD, 0x00]);

        let mut out = [0_u8; 8];
        let written = s.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input);
    }

    #[test]
    fn an_empty_octet_string_is_valid() {
        let (used, s) = Asn1OctetString::try_decode(&[0x04, 0x00], DEPTH).unwrap();
        assert_eq!(used, 2);
        assert!(s.as_bytes().is_empty());
        assert_eq!(s, Asn1OctetString::default());
    }

    #[test]
    fn a_bit_string_tag_is_not_an_octet_string() {
        assert_eq!(
            Asn1OctetString::try_decode(&[0x03, 0x01, 0x00], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
    }
}
