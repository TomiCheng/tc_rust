//! ASN.1 `ENUMERATED`，共用 INTEGER 的最短二補數內容規則。

use alloc::vec::Vec;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{DecodeContent, Encode};

use super::integer_octets::{minimal_signed, validate_integer_octets};
use super::tag::ENUMERATED as TAG;

/// 擁有最短二補數大端序內容的 `ENUMERATED`。
///
/// 獨立持有內容位元組；與 INTEGER 共用內容規則，完整編碼的標籤則是 `0x0A`。
/// 此型別不檢查數值是否列在特定結構定義的列舉項目中；該限制由呼叫端判斷。
/// 內容不限於 64 位元，只有轉成 `i64` 或 `u64` 時才檢查目標範圍。
///
/// # Examples
///
/// 編碼列舉值 5，再解回原值；標籤與 INTEGER 不同。
///
/// ```
/// use tc_asn1::{Asn1Enumerated, Depth, Encode, EncodingType, Decode};
///
/// let value = Asn1Enumerated::from(5_u64);
/// let mut out = [0; 3];
/// value.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, [0x0A, 1, 5]);
/// let (used, decoded) = Asn1Enumerated::try_decode(&out, Depth::DEFAULT).unwrap();
/// assert_eq!(used, out.len());
/// assert_eq!(u64::try_from(&decoded), Ok(5));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Enumerated {
    value: Vec<u8>,
}

impl Asn1Enumerated {
    /// 由最短二補數大端序內容建立，不含 tag 與長度欄位。
    /// 非空且沒有多餘符號位元組才接受，否則回傳 [`Asn1Error::MalformedValue`]。
    /// 變動時間：依內容長度與符號位元組分支。
    ///
    /// # Examples
    ///
    /// 正數 128 需要保留前導 `00`，5 則不允許多放一個 `00`。
    ///
    /// ```
    /// use tc_asn1::{Asn1Enumerated, Asn1Error};
    ///
    /// let value = Asn1Enumerated::from_der_bytes(&[0, 0x80]).unwrap();
    /// assert_eq!(value.as_bytes(), &[0, 0x80]);
    /// assert_eq!(i64::try_from(&value), Ok(128));
    /// assert_eq!(Asn1Enumerated::from_der_bytes(&[0, 5]), Err(Asn1Error::MalformedValue));
    /// ```
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_integer_octets(bytes)?;
        Ok(Self {
            value: bytes.to_vec(),
        })
    }

    /// 借用最短二補數大端序內容，不含 tag 與長度欄位。
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}

impl From<u64> for Asn1Enumerated {
    /// 由無號值建立最短二補數內容，必要時補正號位元組。
    /// 變動時間：依數值的前導零與符號位分支。
    fn from(value: u64) -> Self {
        // 加一個正號位元組後視為九位元組二補數，再共用最短形式的轉換。
        let mut bytes = [0; 9];
        bytes[1..].copy_from_slice(&value.to_be_bytes());
        Self {
            value: minimal_signed(&bytes).to_vec(),
        }
    }
}

impl From<i64> for Asn1Enumerated {
    /// 由有號值建立最短二補數內容。
    /// 變動時間：依多餘的符號位元組分支。
    fn from(value: i64) -> Self {
        Self {
            value: minimal_signed(&value.to_be_bytes()).to_vec(),
        }
    }
}

impl TryFrom<&Asn1Enumerated> for u64 {
    type Error = Asn1Error;

    /// 轉成無號值；負數回傳 [`Asn1Error::MalformedValue`]，超出範圍回傳
    /// [`Asn1Error::LengthOverflow`]。變動時間：依內容長度、符號與數值範圍分支。
    fn try_from(value: &Asn1Enumerated) -> Result<Self, Self::Error> {
        if value.value[0] & 0x80 != 0 {
            return Err(Asn1Error::MalformedValue);
        }
        // 去掉正號位元組；零會留下空切片，摺疊結果仍是零。
        let bytes = value.value.strip_prefix(&[0]).unwrap_or(&value.value);
        if bytes.len() > 8 {
            return Err(Asn1Error::LengthOverflow);
        }
        Ok(bytes
            .iter()
            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte)))
    }
}

impl TryFrom<&Asn1Enumerated> for i64 {
    type Error = Asn1Error;

    /// 轉成有號值；超出範圍回傳 [`Asn1Error::LengthOverflow`]。
    /// 變動時間：依內容長度、符號與數值範圍分支。
    fn try_from(value: &Asn1Enumerated) -> Result<Self, Self::Error> {
        if value.value.len() > 8 {
            return Err(Asn1Error::LengthOverflow);
        }
        let sign = if value.value[0] & 0x80 != 0 { 0xFF } else { 0 };
        let mut bytes = [sign; 8];
        bytes[8 - value.value.len()..].copy_from_slice(&value.value);
        Ok(Self::from_be_bytes(bytes))
    }
}

impl<'a> DecodeContent<'a> for Asn1Enumerated {
    const TAG: &'static [u8] = TAG;

    /// 驗證內容非空且沒有多餘符號位元組，與 INTEGER 共用規則。
    /// 變動時間：依內容長度與符號位元組分支。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        Self::from_der_bytes(value)
    }
}

impl Encode for Asn1Enumerated {
    /// 回傳 ENUMERATED 的識別位元組。
    fn tag(&self) -> &[u8] {
        TAG
    }

    /// 回傳內容位元組數。常數時間：直接讀取已儲存的內容長度。
    fn content_len(&self, _: EncodingType) -> usize {
        self.value.len()
    }

    /// 原樣寫入二補數內容，不含標籤。
    /// 變動時間：複製量由內容長度決定。
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.value.len()].copy_from_slice(&self.value);
        Ok(self.value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Decode;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn an_enumerated_tag_with_content_05_decodes_as_five() {
        let (used, value) = Asn1Enumerated::try_decode(&[0x0A, 1, 5], DEPTH).unwrap();
        assert_eq!(used, 3);
        assert_eq!(u64::try_from(&value), Ok(5));
        assert_eq!(i64::try_from(&value), Ok(5));
    }

    #[test]
    fn an_integer_tag_is_rejected_even_when_its_content_is_valid() {
        assert_eq!(
            Asn1Enumerated::try_decode(&[2, 1, 5], DEPTH),
            Err(Asn1Error::UnexpectedTag)
        );
    }

    #[test]
    fn empty_content_and_redundant_sign_octets_are_rejected() {
        for input in [&[0x0A, 0][..], &[0x0A, 2, 0, 5], &[0x0A, 2, 0xFF, 0x80]] {
            assert_eq!(
                Asn1Enumerated::try_decode(input, DEPTH),
                Err(Asn1Error::MalformedValue)
            );
        }
    }

    #[test]
    fn enumerated_values_round_trip_with_minimal_signed_contents_under_both_rules() {
        for (value, expected) in [
            (0_i64, &[0x0A, 1, 0][..]),
            (5, &[0x0A, 1, 5]),
            (128, &[0x0A, 2, 0, 0x80]),
            (-1, &[0x0A, 1, 0xFF]),
            (-128, &[0x0A, 1, 0x80]),
            (-129, &[0x0A, 2, 0xFF, 0x7F]),
        ] {
            let original = Asn1Enumerated::from(value);
            for rules in [EncodingType::Ber, EncodingType::Der] {
                let mut out = [0; 16];
                let written = original.encode(rules, &mut out).unwrap();
                assert_eq!(&out[..written], expected);
                assert_eq!(written, original.encoded_len(rules));
                assert_eq!(original.content_len(rules), expected.len() - 2);
                let (used, decoded) = Asn1Enumerated::try_decode(&out[..written], DEPTH).unwrap();
                assert_eq!(used, written);
                assert_eq!(decoded, original);
                assert_eq!(i64::try_from(&decoded), Ok(value));
            }
        }
    }

    #[test]
    fn signed_and_unsigned_64_bit_boundaries_survive_encoding_and_decoding() {
        for value in [0, 127, 128, u64::MAX] {
            let original = Asn1Enumerated::from(value);
            let mut out = [0; 11];
            let written = original.encode(EncodingType::Der, &mut out).unwrap();
            let (_, decoded) = Asn1Enumerated::try_decode(&out[..written], DEPTH).unwrap();
            assert_eq!(u64::try_from(&decoded), Ok(value));
        }
        for value in [i64::MIN, i64::MAX] {
            let original = Asn1Enumerated::from(value);
            let mut out = [0; 10];
            let written = original.encode(EncodingType::Der, &mut out).unwrap();
            let (_, decoded) = Asn1Enumerated::try_decode(&out[..written], DEPTH).unwrap();
            assert_eq!(i64::try_from(&decoded), Ok(value));
        }
    }

    #[test]
    fn contents_wider_than_64_bits_are_preserved_but_primitive_conversions_fail() {
        for bytes in [[0x01; 12], [0xFE; 12]] {
            let original = Asn1Enumerated::from_der_bytes(&bytes).unwrap();
            assert_eq!(original.as_bytes(), &bytes);
            assert_eq!(i64::try_from(&original), Err(Asn1Error::LengthOverflow));
            let unsigned_error = if bytes[0] & 0x80 != 0 {
                Asn1Error::MalformedValue
            } else {
                Asn1Error::LengthOverflow
            };
            assert_eq!(u64::try_from(&original), Err(unsigned_error));
            for rules in [EncodingType::Ber, EncodingType::Der] {
                let mut out = [0; 14];
                assert_eq!(original.encode(rules, &mut out), Ok(out.len()));
                assert_eq!(&out[..2], &[0x0A, 12]);
                assert_eq!(&out[2..], &bytes);
                assert_eq!(
                    Asn1Enumerated::try_decode(&out, DEPTH),
                    Ok((14, original.clone()))
                );
            }
        }
    }

    #[test]
    fn conversions_reject_negative_unsigned_values_and_values_outside_the_target_range() {
        assert_eq!(
            u64::try_from(&Asn1Enumerated::from(-1_i64)),
            Err(Asn1Error::MalformedValue)
        );
        assert_eq!(
            i64::try_from(&Asn1Enumerated::from(u64::MAX)),
            Err(Asn1Error::LengthOverflow)
        );
        let (_, too_large) =
            Asn1Enumerated::try_decode(&[0x0A, 9, 1, 0, 0, 0, 0, 0, 0, 0, 0], DEPTH).unwrap();
        assert_eq!(u64::try_from(&too_large), Err(Asn1Error::LengthOverflow));
    }
}
