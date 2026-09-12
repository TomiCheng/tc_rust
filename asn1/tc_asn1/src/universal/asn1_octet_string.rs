//! ASN.1 `OCTET STRING`。

use alloc::vec::Vec;

use crate::asn1_ref::Children;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

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

impl<'a> DecodeContent<'a> for Asn1OctetString {
    const TAG: &'static [u8] = TAG;

    /// 任何內容都合法，包括空的。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        Ok(Self::new(value))
    }

    /// 串接 BER 分段字串，允許巢狀；重編一律使用 primitive 形式。
    /// 變動時間：分支只依編碼結構。
    fn try_decode_constructed(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let mut bytes = Vec::new();
        for child in Children::new(value, depth) {
            let part = child?.decode_as::<Asn1OctetString>(depth)?;
            bytes.extend_from_slice(&part.bytes);
        }
        Ok(Self { bytes })
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
    use crate::traits::Decode;

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
    #[test]
    fn definite_and_indefinite_constructed_octets_flatten_and_encode_as_primitive() {
        for input in [
            &b"\x24\x06\x04\x01\xaa\x04\x01\xbb"[..],
            &b"\x24\x80\x04\x01\xaa\x04\x01\xbb\x00\x00"[..],
        ] {
            let (used, value) = Asn1OctetString::try_decode(input, DEPTH).unwrap();
            assert_eq!(used, input.len());
            assert_eq!(value.as_bytes(), &[0xaa, 0xbb]);
            for rules in [EncodingType::Der, EncodingType::Ber] {
                assert_eq!(value.encode_to_vec(rules).unwrap(), [4, 2, 0xaa, 0xbb]);
            }
            let tree = crate::Asn1Object::try_decode(input, DEPTH).unwrap().1;
            assert_eq!(tree, crate::Asn1Object::OctetString(value));
            assert_eq!(
                alloc::string::ToString::to_string(&tree),
                "OCTET STRING (2 bytes) aabb\n"
            );
        }
    }

    #[test]
    fn nested_constructed_octets_consume_one_depth_unit_per_layer() {
        let input = b"\x24\x80\x24\x03\x04\x01\xaa\x04\x01\xbb\x00\x00";
        assert_eq!(
            Asn1OctetString::try_decode(input, Depth::new(1)),
            Err(Asn1Error::DepthExceeded)
        );
        let (used, value) = Asn1OctetString::try_decode(input, Depth::new(2)).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(value.as_bytes(), &[0xaa, 0xbb]);
    }

    #[test]
    fn constructed_octets_reject_other_component_types_and_allow_no_components() {
        assert_eq!(
            Asn1OctetString::try_decode(b"\x24\x03\x02\x01\xaa", DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            Asn1OctetString::try_decode(b"\x24\x01\x04", DEPTH),
            Err(Asn1Error::Truncated)
        );
        for input in [&b"\x24\x00"[..], &b"\x24\x80\x00\x00"[..]] {
            let value = Asn1OctetString::try_decode_exact(input, DEPTH).unwrap();
            assert!(value.as_bytes().is_empty());
            assert_eq!(value.encode_to_vec(EncodingType::Der).unwrap(), [4, 0]);
        }
    }

    #[test]
    fn sequences_of_octets_accept_constructed_members() {
        let value = crate::Asn1SequenceOf::<Asn1OctetString>::try_decode_exact(
            b"\x30\x05\x24\x03\x04\x01\xaa",
            DEPTH,
        )
        .unwrap();
        assert_eq!(value.members(), &[Asn1OctetString::new(&[0xaa])]);
    }
}
