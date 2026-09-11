//! ASN.1 `BIT STRING`。

use alloc::vec::Vec;

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
}
