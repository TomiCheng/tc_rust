//! ASN.1 `INTEGER`。

use alloc::vec::Vec;

use crate::depth::Depth;
use crate::encoding_type::EncodingType;
use crate::error::Asn1Error;
use crate::traits::{Encode, TryDecodeContent};

use super::tag::INTEGER as TAG;

/// 內容是二補數大端序、最短形式，擁有。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Integer {
    value: Vec<u8>,
}

impl Asn1Integer {
    /// 由已經是 DER 形式的位元組建立；驗證非空且沒有多餘的符號位元組。
    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        match bytes {
            [] => Err(Asn1Error::MalformedValue),
            // 多餘的符號位元組（X.690 8.3.2），BER 也禁止。
            [0x00, next, ..] if next & 0x80 == 0 => Err(Asn1Error::MalformedValue),
            [0xFF, next, ..] if next & 0x80 != 0 => Err(Asn1Error::MalformedValue),
            _ => Ok(Self {
                value: bytes.to_vec(),
            }),
        }
    }

    /// 由無號大端序建立（大數 `to_bytes_be` 的形式）：去前導零，最高位為 1 就補 `00`。
    pub fn from_unsigned_bytes(magnitude: &[u8]) -> Self {
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        let significant = &magnitude[start..];
        let mut value = Vec::with_capacity(significant.len() + 1);
        if significant.first().is_none_or(|b| b & 0x80 != 0) {
            value.push(0x00); // 零是單一個 00；最高位為 1 要補符號位元組
        }
        value.extend_from_slice(significant);
        Self { value }
    }

    /// 由固定寬度的二補數建立：去掉多餘的符號位元組。
    fn from_signed_bytes(twos_complement: &[u8]) -> Self {
        let mut bytes = twos_complement;
        while let [first, next, ..] = bytes {
            let redundant =
                (*first == 0x00 && next & 0x80 == 0) || (*first == 0xFF && next & 0x80 != 0);
            if !redundant {
                break;
            }
            bytes = &bytes[1..];
        }
        Self {
            value: bytes.to_vec(),
        }
    }

    /// 原始內容：二補數，可能為負。
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    pub fn is_negative(&self) -> bool {
        self.value[0] & 0x80 != 0
    }

    /// 無號大端序，去掉為了符號補的前導 `00`。負數回錯誤。
    pub fn as_unsigned_bytes(&self) -> Result<&[u8], Asn1Error> {
        if self.is_negative() {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(match self.value.as_slice() {
            [0x00, rest @ ..] if !rest.is_empty() => rest,
            v => v,
        })
    }

    /// 無號解讀，放不進 `u128` 回 [`Asn1Error::LengthOverflow`]，負數回
    /// [`Asn1Error::MalformedValue`]。
    fn to_u128(&self) -> Result<u128, Asn1Error> {
        let bytes = self.as_unsigned_bytes()?;
        if bytes.len() > 16 {
            return Err(Asn1Error::LengthOverflow);
        }
        Ok(bytes
            .iter()
            .fold(0_u128, |acc, b| (acc << 8) | u128::from(*b)))
    }

    /// 有號解讀，放不進 `i128` 回 [`Asn1Error::LengthOverflow`]。
    fn to_i128(&self) -> Result<i128, Asn1Error> {
        if self.value.len() > 16 {
            return Err(Asn1Error::LengthOverflow);
        }
        let sign: i128 = if self.is_negative() { -1 } else { 0 };
        Ok(self
            .value
            .iter()
            .fold(sign, |acc, b| (acc << 8) | i128::from(*b)))
    }
}

macro_rules! from_unsigned {
    ($($t:ty),*) => {$(
        impl From<$t> for Asn1Integer {
            fn from(n: $t) -> Self {
                Self::from_unsigned_bytes(&n.to_be_bytes())
            }
        }
    )*};
}
macro_rules! from_signed {
    ($($t:ty),*) => {$(
        impl From<$t> for Asn1Integer {
            fn from(n: $t) -> Self {
                Self::from_signed_bytes(&n.to_be_bytes())
            }
        }
    )*};
}
from_unsigned!(u8, u16, u32, u64, u128);
from_signed!(i8, i16, i32, i64, i128);

macro_rules! try_into_unsigned {
    ($($t:ty),*) => {$(
        impl TryFrom<&Asn1Integer> for $t {
            type Error = Asn1Error;
            fn try_from(n: &Asn1Integer) -> Result<Self, Asn1Error> {
                <$t>::try_from(n.to_u128()?).map_err(|_| Asn1Error::LengthOverflow)
            }
        }
    )*};
}
macro_rules! try_into_signed {
    ($($t:ty),*) => {$(
        impl TryFrom<&Asn1Integer> for $t {
            type Error = Asn1Error;
            fn try_from(n: &Asn1Integer) -> Result<Self, Asn1Error> {
                <$t>::try_from(n.to_i128()?).map_err(|_| Asn1Error::LengthOverflow)
            }
        }
    )*};
}
try_into_unsigned!(u8, u16, u32, u64, u128);
try_into_signed!(i8, i16, i32, i64, i128);

impl<'a> TryDecodeContent<'a> for Asn1Integer {
    const TAG: &'static [u8] = TAG;

    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        Self::from_der_bytes(value)
    }
}

impl Encode for Asn1Integer {
    fn tag(&self) -> &[u8] {
        TAG
    }
    fn content_len(&self, _: EncodingType) -> usize {
        self.value.len()
    }
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.value.len()].copy_from_slice(&self.value);
        Ok(self.value.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::TryDecode;

    const DEPTH: Depth = Depth::DEFAULT;

    #[test]
    fn unsigned_primitives_produce_the_minimal_signed_form() {
        assert_eq!(Asn1Integer::from(0_u8).as_bytes(), &[0x00]);
        assert_eq!(Asn1Integer::from(5_u16).as_bytes(), &[0x05]);
        assert_eq!(Asn1Integer::from(127_u32).as_bytes(), &[0x7F]);
        assert_eq!(Asn1Integer::from(128_u64).as_bytes(), &[0x00, 0x80]);
        assert_eq!(Asn1Integer::from(256_u128).as_bytes(), &[0x01, 0x00]);
        assert_eq!(Asn1Integer::from(u8::MAX).as_bytes(), &[0x00, 0xFF]);
        assert_eq!(
            Asn1Integer::from(u128::MAX).as_bytes().len(),
            17,
            "16 個 FF 加一個符號位元組"
        );
    }

    #[test]
    fn signed_primitives_produce_the_minimal_twos_complement_form() {
        assert_eq!(Asn1Integer::from(0_i8).as_bytes(), &[0x00]);
        assert_eq!(Asn1Integer::from(-1_i8).as_bytes(), &[0xFF]);
        assert_eq!(
            Asn1Integer::from(-1_i128).as_bytes(),
            &[0xFF],
            "寬度不影響結果"
        );
        assert_eq!(Asn1Integer::from(-128_i16).as_bytes(), &[0x80]);
        assert_eq!(Asn1Integer::from(-129_i32).as_bytes(), &[0xFF, 0x7F]);
        assert_eq!(Asn1Integer::from(127_i64).as_bytes(), &[0x7F]);
        assert_eq!(Asn1Integer::from(128_i64).as_bytes(), &[0x00, 0x80]);
        assert_eq!(Asn1Integer::from(i8::MIN).as_bytes(), &[0x80]);
        assert_eq!(Asn1Integer::from(i128::MIN).as_bytes().len(), 16);
    }

    #[test]
    fn primitives_round_trip_through_try_from() {
        assert_eq!(u8::try_from(&Asn1Integer::from(255_u8)), Ok(255));
        assert_eq!(u64::try_from(&Asn1Integer::from(256_u64)), Ok(256));
        assert_eq!(u128::try_from(&Asn1Integer::from(u128::MAX)), Ok(u128::MAX));
        assert_eq!(i8::try_from(&Asn1Integer::from(-128_i8)), Ok(-128));
        assert_eq!(i32::try_from(&Asn1Integer::from(-129_i32)), Ok(-129));
        assert_eq!(i128::try_from(&Asn1Integer::from(i128::MIN)), Ok(i128::MIN));
    }

    #[test]
    fn a_value_that_does_not_fit_the_target_is_refused() {
        assert_eq!(
            u8::try_from(&Asn1Integer::from(256_u16)),
            Err(Asn1Error::LengthOverflow)
        );
        assert_eq!(
            i8::try_from(&Asn1Integer::from(128_u8)),
            Err(Asn1Error::LengthOverflow)
        );
        assert_eq!(
            i8::try_from(&Asn1Integer::from(-129_i16)),
            Err(Asn1Error::LengthOverflow)
        );
        // 負數不能當無號
        assert_eq!(
            u8::try_from(&Asn1Integer::from(-1_i8)),
            Err(Asn1Error::MalformedValue)
        );
        // 17 個位元組的正數放不進 u128
        let big = Asn1Integer::from_unsigned_bytes(&[0xFF; 17]);
        assert_eq!(u128::try_from(&big), Err(Asn1Error::LengthOverflow));
    }

    #[test]
    fn the_same_value_from_different_widths_is_equal() {
        assert_eq!(Asn1Integer::from(5_u8), Asn1Integer::from(5_i128));
        assert_eq!(Asn1Integer::from(-1_i8), Asn1Integer::from(-1_i64));
    }

    #[test]
    fn unsigned_bytes_get_the_sign_pad_and_lose_it_again() {
        // RSA modulus 那條路：最高位為 1 的無號位元組進來，補 00；取出時去掉。
        let n = Asn1Integer::from_unsigned_bytes(&[0x80, 0x01]);
        assert_eq!(n.as_bytes(), &[0x00, 0x80, 0x01]);
        assert_eq!(n.as_unsigned_bytes(), Ok(&[0x80, 0x01][..]));

        // 前導零被吃掉，零本身留一個 00。
        assert_eq!(
            Asn1Integer::from_unsigned_bytes(&[0x00, 0x00, 0x05]).as_bytes(),
            &[0x05]
        );
        assert_eq!(
            Asn1Integer::from_unsigned_bytes(&[0x00, 0x00]).as_bytes(),
            &[0x00]
        );
        assert_eq!(Asn1Integer::from_unsigned_bytes(&[]).as_bytes(), &[0x00]);
    }

    #[test]
    fn a_negative_value_is_recognised_and_refused_as_unsigned() {
        let n = Asn1Integer::from_der_bytes(&[0x80]).unwrap(); // -128
        assert!(n.is_negative());
        assert_eq!(n.as_unsigned_bytes(), Err(Asn1Error::MalformedValue));
    }

    #[test]
    fn redundant_sign_bytes_are_rejected_but_necessary_ones_are_not() {
        assert!(Asn1Integer::from_der_bytes(&[0x00, 0x05]).is_err());
        assert!(Asn1Integer::from_der_bytes(&[0xFF, 0x80]).is_err());
        assert!(Asn1Integer::from_der_bytes(&[]).is_err());
        assert!(Asn1Integer::from_der_bytes(&[0x00, 0x80]).is_ok());
        assert!(Asn1Integer::from_der_bytes(&[0xFF, 0x7F]).is_ok());
    }

    #[test]
    fn decode_and_encode_round_trip() {
        let input = [0x02, 0x02, 0x01, 0x00];
        let (used, n) = Asn1Integer::try_decode(&input, DEPTH).unwrap();
        assert_eq!(used, 4);
        assert_eq!(u64::try_from(&n), Ok(256));

        let mut out = [0_u8; 8];
        let written = n.encode(EncodingType::Der, &mut out).unwrap();
        assert_eq!(&out[..written], &input);
        assert_eq!(written, n.encoded_len(EncodingType::Der));
    }

    #[test]
    fn implicit_tagging_writes_the_callers_tag_over_the_same_contents() {
        let mut out = [0_u8; 8];
        let written = Asn1Integer::from(5_u64)
            .encode_tagged(&[0x80], EncodingType::Der, &mut out)
            .unwrap();
        assert_eq!(&out[..written], &[0x80, 0x01, 0x05]);
    }
}
