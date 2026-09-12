//! ASN.1 `BIT STRING`。

use alloc::vec::Vec;

use crate::asn1_ref::Children;
use crate::decoding_options::DecodingOptions;
use crate::encoding_options::EncodingOptions;
use crate::error::Asn1Error;
use crate::traits::{DecodeConstructed, DecodeContent, Encode};

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

impl<'a> crate::Decode<'a> for Asn1BitString {
    fn try_decode(
        buff: &'a [u8],
        options: crate::DecodingOptions,
    ) -> Result<(usize, Self), crate::Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, options)?;
        let value = if element.is_constructed() {
            <Self as crate::DecodeConstructed<'a>>::try_decode_constructed(
                element.value(),
                options,
            )?
        } else {
            <Self as crate::DecodeContent<'a>>::try_decode_content(element.value(), options)?
        };
        Ok((element.total_len(), value))
    }
}

impl<'a> DecodeContent<'a> for Asn1BitString {
    /// 寬鬆照 BER：沒用到的位不是 0 也接受，存起來時清掉。
    fn try_decode_content(value: &'a [u8], options: DecodingOptions) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
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

impl<'a> DecodeConstructed<'a> for Asn1BitString {
    /// 串接 BER 分段字串，巢狀分段透過新的 constructed 解碼入口處理。
    /// 除最後一個成分外，未用位元數必須為零，否則回傳 `MalformedValue`。
    /// 變動時間：分支只依編碼結構，只能用於公開值；沒有常數時間替代方法。
    fn try_decode_constructed(
        value: &'a [u8],
        options: DecodingOptions,
    ) -> Result<Self, Asn1Error> {
        options.check_content_len(value.len())?;
        let options = options.descend()?;
        let mut bytes = Vec::new();
        let mut unused_bits = 0;
        for child in Children::new(value, options) {
            if unused_bits != 0 {
                return Err(Asn1Error::MalformedValue);
            }
            let child = child?;
            if child.tag() != TAG && child.tag() != crate::tag::CONSTRUCTED_BIT_STRING {
                return Err(Asn1Error::UnexpectedTag);
            }
            let part = if child.is_constructed() {
                child.decode_constructed_as::<Self>(options)?
            } else {
                child.decode_as::<Self>(options)?
            };
            unused_bits = part.unused_bits;
            bytes.extend_from_slice(&part.bytes);
        }
        Ok(Self { bytes, unused_bits })
    }
}

impl crate::EncodeContent for Asn1BitString {
    /// Length of the contents, including segment headers for long CER values.
    /// The CER threshold includes the unused-bit count: 999 data octets remain primitive.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn content_len(&self, rules: EncodingOptions) -> usize {
        if rules != EncodingOptions::Cer || self.bytes.len() < 1000 {
            return 1 + self.bytes.len();
        }
        self.bytes
            .chunks(999)
            .map(|part| 1 + crate::encoding::len_octets(part.len() + 1) + 1 + part.len())
            .sum()
    }

    /// Write primitive contents, or primitive segment TLVs when CER contents exceed 1000 octets.
    /// Each nonfinal segment has 999 data octets and zero unused bits; only the final segment
    /// carries the value's unused-bit count. Neither form includes the outer header or EOC.
    /// BER (either length form) and DER always use primitive contents.
    /// Variable time: public values only; no constant-time alternative is provided.
    fn encode_content(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let total = self.content_len(rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        if rules != EncodingOptions::Cer || self.bytes.len() < 1000 {
            out[0] = self.unused_bits;
            out[1..].copy_from_slice(&self.bytes);
            return Ok(total);
        }
        let mut at = 0;
        let count = self.bytes.len().div_ceil(999);
        for (index, part) in self.bytes.chunks(999).enumerate() {
            out[at] = TAG[0];
            at += 1;
            at += crate::encoding::write_len(part.len() + 1, &mut out[at..]);
            out[at] = if index + 1 == count {
                self.unused_bits
            } else {
                0
            };
            at += 1;
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        Ok(at)
    }
}

impl crate::EncodeTagged for Asn1BitString {
    /// Variable time: branches only on the encoding structure.
    fn encoded_len_tagged(&self, tag: &[u8], rules: EncodingOptions) -> usize {
        if rules != EncodingOptions::Cer || self.bytes.len() < 1000 {
            return crate::encoding::default_encoded_len(self, tag, rules);
        }
        tag.len()
            + 3
            + self
                .bytes
                .chunks(999)
                .map(|part| 1 + crate::encoding::len_octets(part.len() + 1) + 1 + part.len())
                .sum::<usize>()
    }

    /// Each nonfinal segment carries zero unused bits and 999 data octets.
    /// Variable time: branches only on the encoding structure.
    fn encode_tagged(
        &self,
        tag: &[u8],
        rules: EncodingOptions,
        out: &mut [u8],
    ) -> Result<usize, Asn1Error> {
        if rules != EncodingOptions::Cer || self.bytes.len() < 1000 {
            return crate::encoding::default_encode(self, tag, rules, out);
        }
        let total = self.encoded_len_tagged(tag, rules);
        let out = out.get_mut(..total).ok_or(Asn1Error::BufferTooSmall)?;
        out[..tag.len()].copy_from_slice(tag);
        out[0] |= 0x20;
        out[tag.len()] = 0x80;
        let mut at = tag.len() + 1;
        let count = self.bytes.len().div_ceil(999);
        for (index, part) in self.bytes.chunks(999).enumerate() {
            out[at] = TAG[0];
            at += 1;
            at += crate::encoding::write_len(part.len() + 1, &mut out[at..]);
            out[at] = if index + 1 == count {
                self.unused_bits
            } else {
                0
            };
            at += 1;
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        out[at..].fill(0);
        Ok(total)
    }
}

impl Encode for Asn1BitString {
    fn encoded_len(&self, rules: EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, TAG, rules)
    }

    fn encode(&self, rules: EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, TAG, rules, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncodeContent;
    use crate::traits::Decode;

    const OPTIONS: DecodingOptions =
        DecodingOptions::new(crate::Depth::DEFAULT, 16 * 1024 * 1024, 65_536);

    #[test]
    fn content_encoding_keeps_empty_short_and_non_cer_values_primitive() {
        for data_len in [0, 1, 999, 1000] {
            let value = Asn1BitString::from_bits(
                &alloc::vec![0xff; data_len],
                (data_len * 8).saturating_sub(3),
            );
            let mut expected = alloc::vec![value.unused_bits()];
            expected.extend_from_slice(value.as_bytes());
            for options in [
                EncodingOptions::Ber(crate::LengthForm::Definite),
                EncodingOptions::Ber(crate::LengthForm::Indefinite),
                EncodingOptions::Der,
                EncodingOptions::Cer,
            ] {
                if options == EncodingOptions::Cer && data_len == 1000 {
                    continue;
                }
                let encoder: &dyn EncodeContent = &value;
                assert_eq!(encoder.content_len(options), expected.len());
                let mut out = alloc::vec![0xaa; expected.len() + 2];
                assert_eq!(
                    encoder.encode_content(options, &mut out),
                    Ok(expected.len())
                );
                assert_eq!(&out[..expected.len()], expected);
                assert_eq!(&out[expected.len()..], &[0xaa; 2]);
            }
        }
    }

    #[test]
    fn cer_content_encoding_writes_segment_headers_but_no_outer_header_or_end_marker() {
        let mut bytes = [0xaa; 1000];
        bytes[999] = 0xf0;
        let value = Asn1BitString::from_bits(&bytes, 7996);
        let mut expected = alloc::vec![3, 0x82, 3, 0xe8, 0];
        expected.extend_from_slice(&bytes[..999]);
        expected.extend_from_slice(&[3, 2, 4, 0xf0]);
        assert_eq!(expected.len(), 1008);
        let options = EncodingOptions::Cer;
        assert_eq!(value.content_len(options), expected.len());
        let mut out = alloc::vec![0xaa; expected.len() + 2];
        assert_eq!(value.encode_content(options, &mut out), Ok(expected.len()));
        assert_eq!(&out[..expected.len()], expected);
        assert_eq!(&out[expected.len()..], &[0xaa; 2]);
        assert_eq!(
            Asn1BitString::try_decode_constructed(&expected, OPTIONS),
            Ok(value)
        );
    }

    #[test]
    fn cer_content_encoding_handles_full_final_segments_and_rejects_short_buffers() {
        for data_len in [0, 1, 999, 1000, 1998, 1999] {
            let value = Asn1BitString::from_bits(
                &alloc::vec![0xff; data_len],
                (data_len * 8).saturating_sub(7),
            );
            let options = EncodingOptions::Cer;
            let len = value.content_len(options);
            let mut out = alloc::vec![0; len];
            assert_eq!(value.encode_content(options, &mut out), Ok(len));
            let wire = value.encode_to_vec(options).unwrap();
            let element = crate::Asn1Ref::parse(&wire, OPTIONS).unwrap();
            assert_eq!(out, element.value());
            let mut short = alloc::vec![0xaa; len - 1];
            assert_eq!(
                value.encode_content(options, &mut short),
                Err(Asn1Error::BufferTooSmall)
            );
            assert!(short.iter().all(|byte| *byte == 0xaa));
        }
    }

    #[test]
    fn cer_bits_count_the_pad_octet_and_keep_padding_only_in_the_final_segment() {
        let short = Asn1BitString::from_bytes(&[0xaa; 999]);
        let mut expected = alloc::vec![3, 0x82, 3, 0xe8, 0];
        expected.extend_from_slice(&[0xaa; 999]);
        assert_eq!(short.encode_to_vec(EncodingOptions::Cer).unwrap(), expected);
        let mut bytes = [0xaa; 1000];
        bytes[999] = 0xf0;
        let value = Asn1BitString::from_bits(&bytes, 7996);
        let mut expected = alloc::vec![0x23, 0x80, 3, 0x82, 3, 0xe8, 0];
        expected.extend_from_slice(&bytes[..999]);
        expected.extend_from_slice(&[3, 2, 4, 0xf0, 0, 0]);
        assert_eq!(expected.len(), 1012);
        assert_eq!(value.encoded_len(EncodingOptions::Cer), 1012);
        assert_eq!(value.encode_to_vec(EncodingOptions::Cer).unwrap(), expected);
        assert_eq!(
            value.encode(EncodingOptions::Cer, &mut [0; 1011]),
            Err(Asn1Error::BufferTooSmall)
        );
        assert_eq!(
            Asn1BitString::try_decode(&expected, OPTIONS).map(|(_, value)| value),
            Ok(value.clone())
        );
        assert_eq!(
            crate::Asn1Object::try_decode(&expected, OPTIONS).map(|(_, value)| value),
            Ok(value.clone().into())
        );
        let mut definite = alloc::vec![3, 0x82, 3, 0xe9, 4];
        definite.extend_from_slice(&bytes);
        for rules in [
            EncodingOptions::Ber(crate::LengthForm::Definite),
            EncodingOptions::Der,
        ] {
            assert_eq!(value.encode_to_vec(rules).unwrap(), definite);
        }
    }

    #[test]
    fn a_whole_number_of_bytes_has_no_unused_bits() {
        let (used, bits) =
            Asn1BitString::try_decode(&[0x03, 0x03, 0x00, 0xA0, 0x5B], OPTIONS).unwrap();
        assert_eq!(used, 5);
        assert_eq!(bits.as_bytes(), &[0xA0, 0x5B]);
        assert_eq!(bits.bit_len(), 16);
        assert_eq!(bits.unused_bits(), 0);
    }

    #[test]
    fn bit_zero_is_the_high_bit_of_the_first_byte() {
        // KeyUsage = digitalSignature(0)：03 02 07 80
        let (_, bits) = Asn1BitString::try_decode(&[0x03, 0x02, 0x07, 0x80], OPTIONS).unwrap();
        assert_eq!(bits.bit_len(), 1);
        assert!(bits.bit(0));
        assert!(!bits.bit(1), "超出範圍是 false");

        // 0100 0000 加 6 位未用 = 01
        let (_, bits) = Asn1BitString::try_decode(&[0x03, 0x02, 0x06, 0x40], OPTIONS).unwrap();
        assert!(!bits.bit(0));
        assert!(bits.bit(1));
        assert_eq!(bits.bit_len(), 2);
    }

    #[test]
    fn an_empty_bit_string_is_just_the_count_byte() {
        let (used, bits) = Asn1BitString::try_decode(&[0x03, 0x01, 0x00], OPTIONS).unwrap();
        assert_eq!(used, 3);
        assert_eq!(bits.bit_len(), 0);
        assert!(bits.as_bytes().is_empty());
    }

    #[test]
    fn unused_bits_that_are_set_are_accepted_and_cleared() {
        // 03 02 06 7F 不是 DER（未用的 6 位不是 0），但是合法 BER。
        let (_, bits) = Asn1BitString::try_decode(&[0x03, 0x02, 0x06, 0x7F], OPTIONS).unwrap();
        assert_eq!(bits.as_bytes(), &[0x40], "存起來時清掉");

        let mut out = [0_u8; 8];
        let written = bits.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &[0x03, 0x02, 0x06, 0x40], "重編就是 DER");
    }

    #[test]
    fn malformed_counts_are_rejected() {
        assert!(
            Asn1BitString::try_decode_content(&[], OPTIONS).is_err(),
            "沒有計數位元組"
        );
        assert!(
            Asn1BitString::try_decode_content(&[0x08, 0xFF], OPTIONS).is_err(),
            "計數 > 7"
        );
        assert!(
            Asn1BitString::try_decode_content(&[0x03], OPTIONS).is_err(),
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
        let written = original.encode(EncodingOptions::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &[0x03, 0x03, 0x04, 0xA5, 0xF0]);

        let (_, decoded) = Asn1BitString::try_decode(&out[..written], OPTIONS).unwrap();
        assert_eq!(decoded, original);
    }
    fn decode_constructed(
        input: &[u8],
        depth: DecodingOptions,
    ) -> Result<(usize, Asn1BitString), Asn1Error> {
        let element = crate::Asn1Ref::parse(input, depth)?;
        Ok((element.total_len(), element.decode_constructed_as(depth)?))
    }

    #[test]
    fn constructed_bits_preserve_only_the_last_components_unused_bit_count() {
        for input in [
            &b"\x23\x08\x03\x02\x00\xf0\x03\x02\x04\xa0"[..],
            &b"\x23\x80\x03\x02\x00\xf0\x03\x02\x04\xa0\x00\x00"[..],
            &b"\x23\x0a\x03\x02\x00\xf0\x23\x04\x03\x02\x04\xa0"[..],
        ] {
            let (used, bits) = decode_constructed(input, OPTIONS).unwrap();
            assert_eq!(
                Asn1BitString::try_decode(input, OPTIONS),
                Ok((used, bits.clone()))
            );
            assert_eq!(used, input.len());
            assert_eq!(bits.as_bytes(), &[0xf0, 0xa0]);
            assert_eq!(bits.unused_bits(), 4);
            assert_eq!(bits.bit_len(), 12);
            assert_eq!(
                bits.encode_to_vec(EncodingOptions::Der).unwrap(),
                [3, 3, 4, 0xf0, 0xa0]
            );
            let tree = crate::Asn1Object::try_decode(input, OPTIONS)
                .map(|(_, value)| value)
                .unwrap();
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
                decode_constructed(input, OPTIONS),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn empty_constructed_bits_are_valid_but_wrong_components_and_excessive_depth_are_not() {
        for input in [&b"\x23\x00"[..], &b"\x23\x80\x00\x00"[..]] {
            let bits = decode_constructed(input, OPTIONS)
                .map(|(_, value)| value)
                .unwrap();
            assert_eq!(bits.bit_len(), 0);
            assert_eq!(bits.unused_bits(), 0);
            assert_eq!(bits.encode_to_vec(EncodingOptions::Der).unwrap(), [3, 1, 0]);
        }
        assert_eq!(
            decode_constructed(b"\x23\x03\x04\x01\x00", OPTIONS),
            Err(Asn1Error::UnexpectedTag)
        );
        assert_eq!(
            decode_constructed(b"\x23\x02\x03\x00", OPTIONS),
            Err(Asn1Error::MalformedValue)
        );
        let input = b"\x23\x02\x23\x00";
        assert_eq!(
            decode_constructed(
                input,
                DecodingOptions::new(crate::Depth::new(1), 16 * 1024 * 1024, 65_536)
            ),
            Err(Asn1Error::DepthExceeded)
        );
        assert!(
            decode_constructed(
                input,
                DecodingOptions::new(crate::Depth::new(2), 16 * 1024 * 1024, 65_536)
            )
            .is_ok()
        );
    }
    #[test]
    fn the_constructed_entry_flattens_nested_bits_and_enforces_padding_tags_and_depth() {
        for (input, depth, expected) in [
            (
                &b"\x23\x08\x03\x02\x00\xf0\x03\x02\x04\xa0"[..],
                1,
                Ok(Asn1BitString::from_bits(&[0xf0, 0xa0], 12)),
            ),
            (
                &b"\x23\x80\x03\x02\x00\xf0\x23\x04\x03\x02\x04\xa0\x00\x00"[..],
                2,
                Ok(Asn1BitString::from_bits(&[0xf0, 0xa0], 12)),
            ),
            (&b"\x23\x00"[..], 1, Ok(Asn1BitString::from_bytes(&[]))),
            (
                &b"\x23\x08\x03\x02\x04\xf0\x03\x02\x00\xa0"[..],
                1,
                Err(Asn1Error::MalformedValue),
            ),
            (
                &b"\x23\x03\x04\x01\x00"[..],
                1,
                Err(Asn1Error::UnexpectedTag),
            ),
            (&b"\x23\x02\x24\x00"[..], 2, Err(Asn1Error::UnexpectedTag)),
            (&b"\x03\x01\x00"[..], 1, Err(Asn1Error::UnexpectedTag)),
            (&b"\x23\x02\x23\x00"[..], 1, Err(Asn1Error::DepthExceeded)),
            (
                &b"\x23\x02\x23\x00"[..],
                2,
                Ok(Asn1BitString::from_bytes(&[])),
            ),
        ] {
            let element = crate::Asn1Ref::parse(input, OPTIONS).unwrap();
            assert_eq!(
                element.decode_constructed_as::<Asn1BitString>(DecodingOptions::new(
                    crate::Depth::new(depth),
                    16 * 1024 * 1024,
                    65_536
                )),
                expected,
                "{input:?}"
            );
        }
    }
}
