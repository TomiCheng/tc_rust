//! ASN.1 `BIT STRING`。

use alloc::vec::Vec;

use crate::asn1_ref::Children;
use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::BIT_STRING as TAG;

/// 位元 0 是第一個位元組的最高位。最後一個位元組沒用到的位永遠存成 0。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1BitString {
    unused_bits: u8,
    bytes: Vec<u8>,
}

impl Asn1BitString {
    /// 整數個位元組，沒有未用的位 —— 公鑰、簽章這種容器用法。
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            unused_bits: 0,
            bytes: bytes.to_vec(),
        }
    }

    /// 前 `bit_len` 位有效，其餘清零。`bit_len` 超過 `bytes` 能裝的就截到上限。
    pub fn from_bits(bytes: &[u8], bit_len: usize) -> Self {
        let byte_len = bit_len.div_ceil(8).min(bytes.len());
        let bit_len = bit_len.min(byte_len * 8);
        let unused_bits = (byte_len * 8 - bit_len) as u8;
        let mut bytes = bytes[..byte_len].to_vec();
        mask_unused(&mut bytes, unused_bits);
        Self { unused_bits, bytes }
    }

    /// 位元組內容，不含計數位元組。
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn unused_bits(&self) -> u8 {
        self.unused_bits
    }

    pub fn bit_len(&self) -> usize {
        self.bytes.len() * 8 - usize::from(self.unused_bits)
    }

    /// 第 `index` 位；超出範圍回 `false`。
    pub fn bit(&self, index: usize) -> bool {
        index < self.bit_len() && self.bytes[index / 8] & (0x80 >> (index % 8)) != 0
    }
}

/// 把最後一個位元組沒用到的位清零。
fn mask_unused(bytes: &mut [u8], unused_bits: u8) {
    if let Some(last) = bytes.last_mut() {
        *last &= 0xFF << unused_bits;
    }
}

impl<'a> TryDecodeContent<'a> for Asn1BitString {
    const TAG: &'static [u8] = TAG;

    /// 寬鬆照 BER：沒用到的位不是 0 也接受，存起來時清掉。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        let (unused_bits, data) = value.split_first().ok_or(Asn1Error::MalformedValue)?;
        if *unused_bits > 7 || (data.is_empty() && *unused_bits != 0) {
            return Err(Asn1Error::MalformedValue);
        }
        let mut bytes = data.to_vec();
        mask_unused(&mut bytes, *unused_bits);
        Ok(Self {
            unused_bits: *unused_bits,
            bytes,
        })
    }

    /// 串接 BER 分段字串，允許巢狀；重編一律使用 primitive 形式。
    /// 除最後一個成分外，未用位元數必須為零，否則回傳 `MalformedValue`。
    /// 變動時間：分支只依編碼結構。
    fn try_decode_constructed(value: &'a [u8], depth: Depth) -> Result<Self, Asn1Error> {
        let depth = depth.descend()?;
        let mut bytes = Vec::new();
        let mut unused_bits = 0;
        for child in Children::new(value, depth) {
            if unused_bits != 0 {
                return Err(Asn1Error::MalformedValue);
            }
            let part = child?.decode_as::<Asn1BitString>(depth)?;
            unused_bits = part.unused_bits;
            bytes.extend_from_slice(&part.bytes);
        }
        Ok(Self { bytes, unused_bits })
    }
}

impl Encode for Asn1BitString {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingType) -> usize {
        1 + self.bytes.len()
    }
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[0] = self.unused_bits;
        out[1..=self.bytes.len()].copy_from_slice(&self.bytes);
        Ok(1 + self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TryDecode;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn a_whole_number_of_bytes_has_no_unused_bits() {
        let (used, bits) =
            Asn1BitString::try_decode(&[0x03, 0x03, 0x00, 0xA0, 0x5B], DEPTH).unwrap();
        assert_eq!(used, 5);
        assert_eq!(bits.as_bytes(), &[0xA0, 0x5B]);
        assert_eq!(bits.bit_len(), 16);
        assert_eq!(bits.unused_bits(), 0);
    }

    #[test]
    fn bit_zero_is_the_high_bit_of_the_first_byte() {
        // KeyUsage = digitalSignature(0)：03 02 07 80
        let (_, bits) = Asn1BitString::try_decode(&[0x03, 0x02, 0x07, 0x80], DEPTH).unwrap();
        assert_eq!(bits.bit_len(), 1);
        assert!(bits.bit(0));
        assert!(!bits.bit(1), "超出範圍是 false");

        // 0100 0000 加 6 位未用 = 01
        let (_, bits) = Asn1BitString::try_decode(&[0x03, 0x02, 0x06, 0x40], DEPTH).unwrap();
        assert!(!bits.bit(0));
        assert!(bits.bit(1));
        assert_eq!(bits.bit_len(), 2);
    }

    #[test]
    fn an_empty_bit_string_is_just_the_count_byte() {
        let (used, bits) = Asn1BitString::try_decode(&[0x03, 0x01, 0x00], DEPTH).unwrap();
        assert_eq!(used, 3);
        assert_eq!(bits.bit_len(), 0);
        assert!(bits.as_bytes().is_empty());
    }

    #[test]
    fn unused_bits_that_are_set_are_accepted_and_cleared() {
        // 03 02 06 7F 不是 DER（未用的 6 位不是 0），但是合法 BER。
        let (_, bits) = Asn1BitString::try_decode(&[0x03, 0x02, 0x06, 0x7F], DEPTH).unwrap();
        assert_eq!(bits.as_bytes(), &[0x40], "存起來時清掉");

        let mut out = [0_u8; 8];
        let written = bits.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &[0x03, 0x02, 0x06, 0x40], "重編就是 DER");
    }

    #[test]
    fn malformed_counts_are_rejected() {
        assert!(
            Asn1BitString::try_decode_content(&[], DEPTH).is_err(),
            "沒有計數位元組"
        );
        assert!(
            Asn1BitString::try_decode_content(&[0x08, 0xFF], DEPTH).is_err(),
            "計數 > 7"
        );
        assert!(
            Asn1BitString::try_decode_content(&[0x03], DEPTH).is_err(),
            "沒資料卻說有未用的位"
        );
    }

    #[test]
    fn from_bits_masks_and_from_bytes_does_not_need_to() {
        let bits = Asn1BitString::from_bits(&[0xFF, 0xFF], 10);
        assert_eq!(bits.as_bytes(), &[0xFF, 0xC0]);
        assert_eq!(bits.unused_bits(), 6);
        assert_eq!(bits.bit_len(), 10);

        let bits = Asn1BitString::from_bytes(&[0xDE, 0xAD]);
        assert_eq!(bits.bit_len(), 16);
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let original = Asn1BitString::from_bits(&[0xA5, 0xFF], 12);
        let mut out = [0_u8; 8];
        let written = original.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &[0x03, 0x03, 0x04, 0xA5, 0xF0]);

        let (_, decoded) = Asn1BitString::try_decode(&out[..written], DEPTH).unwrap();
        assert_eq!(decoded, original);
    }
    #[test]
    fn constructed_bits_preserve_only_the_last_components_unused_bit_count() {
        for input in [
            &b"\x23\x08\x03\x02\x00\xf0\x03\x02\x04\xa0"[..],
            &b"\x23\x80\x03\x02\x00\xf0\x03\x02\x04\xa0\x00\x00"[..],
            &b"\x23\x0a\x03\x02\x00\xf0\x23\x04\x03\x02\x04\xa0"[..],
        ] {
            let (used, bits) = Asn1BitString::try_decode(input, DEPTH).unwrap();
            assert_eq!(used, input.len());
            assert_eq!(bits.as_bytes(), &[0xf0, 0xa0]);
            assert_eq!(bits.unused_bits(), 4);
            assert_eq!(bits.bit_len(), 12);
            assert_eq!(
                bits.encode_to_vec(EncodingType::Der).unwrap(),
                [3, 3, 4, 0xf0, 0xa0]
            );
            let tree = crate::Asn1Object::try_decode_exact(input, DEPTH).unwrap();
            assert_eq!(tree, crate::Asn1Object::BitString(bits));
            assert_eq!(
                alloc::string::ToString::to_string(&tree),
                "BIT STRING (12 bits) f0a0\n"
            );
        }
    }

    #[test]
    fn nonfinal_bit_components_must_be_byte_aligned_even_before_an_empty_component() {
        for input in [
            &b"\x23\x08\x03\x02\x04\xf0\x03\x02\x00\xa0"[..],
            &b"\x23\x07\x03\x02\x04\xf0\x03\x01\x00"[..],
            &b"\x23\x0a\x23\x04\x03\x02\x04\xf0\x03\x02\x00\xa0"[..],
        ] {
            assert_eq!(
                Asn1BitString::try_decode(input, DEPTH),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn empty_constructed_bits_are_valid_but_wrong_components_and_excessive_depth_are_not() {
        for input in [&b"\x23\x00"[..], &b"\x23\x80\x00\x00"[..]] {
            let bits = Asn1BitString::try_decode_exact(input, DEPTH).unwrap();
            assert_eq!(bits.bit_len(), 0);
            assert_eq!(bits.unused_bits(), 0);
            assert_eq!(bits.encode_to_vec(EncodingType::Der).unwrap(), [3, 1, 0]);
        }
        assert_eq!(
            Asn1BitString::try_decode(b"\x23\x03\x04\x01\x00", DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            Asn1BitString::try_decode(b"\x23\x02\x03\x00", DEPTH),
            Err(Asn1Error::MalformedValue)
        );
        let input = b"\x23\x02\x23\x00";
        assert_eq!(
            Asn1BitString::try_decode(input, Depth::new(1)),
            Err(Asn1Error::DepthExceeded)
        );
        assert!(Asn1BitString::try_decode(input, Depth::new(2)).is_ok());
    }
}
