//! ASN.1 REAL：精確保存二進位與十進位有限值，以及無窮大、NaN、正負零。
//!
//! 存的是正規 DER 內容，不做四則運算，也不依賴大數算術 crate。有限值不受 f64
//! 精度限制；二進位指數遵守線路格式最多 255 個位元組的限制。所有解析、正規化與
//! 轉換都是變動時間，只能用於公開值。

use super::{
    integer_octets::validate_integer_octets,
    real_number::{Exponent, Magnitude},
    tag::REAL as TAG,
};
use crate::{Asn1Error, DecodeContent, Depth, Encode, EncodingType};
use alloc::{vec, vec::Vec};

/// 已正規化的 REAL 編碼。相等比較採 DER 表示：二進位與十進位表示保持區別；
/// 正負零不同，NaN 正規化成單一 ASN.1 值，不保留 IEEE NaN payload。
///
/// # Examples
/// ```
/// use tc_asn1::{Asn1Real, Asn1Error, Encode, EncodingType};
/// let exact = Asn1Real::from_decimal_parts(false, "1", "-1").unwrap();
/// assert_eq!(f64::try_from(&exact), Err(Asn1Error::InexactValue));
/// let half = Asn1Real::from(1.5_f64);
/// let mut out = [0; 5];
/// half.encode(EncodingType::Der, &mut out).unwrap();
/// assert_eq!(out, [9, 3, 0x80, 0xFF, 3]);
/// assert_eq!(f64::try_from(&half), Ok(1.5));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Asn1Real {
    contents: Vec<u8>,
}

impl Asn1Real {
    /// 建立 `(-1)^negative × mantissa × 2^exponent`。
    /// mantissa 是無號大端序，exponent 是非空二補數大端序。變動時間：正規化尾端零位元。
    pub fn from_binary_parts(
        negative: bool,
        mantissa: &[u8],
        exponent: &[u8],
    ) -> Result<Self, Asn1Error> {
        binary(negative, mantissa, Exponent::binary(exponent)?)
    }
    /// 建立 `(-1)^negative × mantissa × 10^exponent`。
    /// mantissa 是非空 ASCII 數字，exponent 可帶正負號。變動時間：正規化十進位位數。
    pub fn from_decimal_parts(
        negative: bool,
        mantissa: &str,
        exponent: &str,
    ) -> Result<Self, Asn1Error> {
        decimal(negative, mantissa.as_bytes(), Exponent::decimal(exponent)?)
    }
    /// 僅接受已正規化的 DER 內容，不含 tag 或長度。變動時間：解碼後比較正規形式。
    pub fn from_der_bytes(contents: &[u8]) -> Result<Self, Asn1Error> {
        let value = decode(contents)?;
        if value.contents != contents {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(value)
    }
    /// 借用正規 DER 內容。
    pub fn as_bytes(&self) -> &[u8] {
        &self.contents
    }
}

fn zero(negative: bool) -> Asn1Real {
    Asn1Real {
        contents: if negative { vec![0x43] } else { Vec::new() },
    }
}

fn binary(negative: bool, mantissa: &[u8], mut exponent: Exponent) -> Result<Asn1Real, Asn1Error> {
    let start = mantissa
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(mantissa.len());
    let mantissa = &mantissa[start..];
    if mantissa.is_empty() {
        return Ok(zero(negative));
    }
    let end = mantissa
        .iter()
        .rposition(|b| *b != 0)
        .expect("nonzero mantissa")
        + 1;
    let shift = mantissa[end - 1].trailing_zeros();
    exponent.adjust(
        false,
        (mantissa.len() - end)
            .checked_mul(8)
            .and_then(|n| n.checked_add(shift as usize))
            .ok_or(Asn1Error::LengthOverflow)?,
    );
    let mut number = Vec::with_capacity(end);
    let mut carry = 0_u16;
    for byte in &mantissa[..end] {
        let next = (carry << 8) | u16::from(*byte);
        number.push((next >> shift) as u8);
        carry = next & ((1 << shift) - 1);
    }
    if number.first() == Some(&0) {
        number.remove(0);
    }
    let exp = exponent.binary_bytes();
    if exp.len() > 255 {
        return Err(Asn1Error::LengthOverflow);
    }
    let format = if exp.len() <= 3 {
        exp.len() as u8 - 1
    } else {
        3
    };
    let mut contents = vec![0x80 | if negative { 0x40 } else { 0 } | format];
    if format == 3 {
        contents.push(exp.len() as u8);
    }
    contents.extend_from_slice(&exp);
    contents.extend_from_slice(&number);
    Ok(Asn1Real { contents })
}

fn decimal(negative: bool, digits: &[u8], mut exponent: Exponent) -> Result<Asn1Real, Asn1Error> {
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(Asn1Error::MalformedValue);
    }
    let start = digits
        .iter()
        .position(|b| *b != b'0')
        .unwrap_or(digits.len());
    if start == digits.len() {
        return Ok(zero(negative));
    }
    let end = digits
        .iter()
        .rposition(|b| *b != b'0')
        .expect("nonzero digits")
        + 1;
    exponent.adjust(false, digits.len() - end);
    let mut contents = vec![3];
    if negative {
        contents.push(b'-');
    }
    contents.extend_from_slice(&digits[start..end]);
    contents.extend_from_slice(b".E");
    let exp = exponent.decimal_text();
    if exp == "0" {
        contents.push(b'+');
    }
    contents.extend_from_slice(exp.as_bytes());
    Ok(Asn1Real { contents })
}

fn decimal_parts(contents: &[u8]) -> Result<(bool, Vec<u8>, Exponent), Asn1Error> {
    let text = core::str::from_utf8(&contents[1..])
        .map_err(|_| Asn1Error::MalformedValue)?
        .trim_start_matches(' ');
    let (negative, text) = if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    let (number, exp) = match contents[0] {
        1 | 2 => (text, "0"),
        3 => text
            .split_once(['E', 'e'])
            .ok_or(Asn1Error::MalformedValue)?,
        _ => return Err(Asn1Error::MalformedValue),
    };
    if contents[0] == 3
        && exp
            .trim_start_matches(['+', '-'])
            .bytes()
            .all(|b| b == b'0')
        && !exp.starts_with('+')
    {
        return Err(Asn1Error::MalformedValue);
    }
    let mut exponent = Exponent::decimal(exp)?;
    let mut digits = Vec::new();
    let mut fractional = None;
    for b in number.bytes() {
        if b == b'.' || b == b',' {
            if fractional.is_some() || contents[0] == 1 {
                return Err(Asn1Error::MalformedValue);
            }
            fractional = Some(0_usize);
        } else if b.is_ascii_digit() {
            digits.push(b);
            if let Some(n) = &mut fractional {
                *n += 1;
            }
        } else {
            return Err(Asn1Error::MalformedValue);
        }
    }
    if contents[0] != 1 && fractional.is_none() {
        return Err(Asn1Error::MalformedValue);
    }
    exponent.adjust(true, fractional.unwrap_or(0));
    Ok((negative, digits, exponent))
}

fn binary_parts(contents: &[u8]) -> Result<(bool, &[u8], Exponent), Asn1Error> {
    let first = contents[0];
    let factor = match (first >> 4) & 3 {
        0 => 1,
        1 => 3,
        2 => 4,
        _ => return Err(Asn1Error::MalformedValue),
    };
    let (at, len) = if first & 3 == 3 {
        (
            2,
            usize::from(*contents.get(1).ok_or(Asn1Error::MalformedValue)?),
        )
    } else {
        (1, usize::from(first & 3) + 1)
    };
    if len == 0 || contents.len() <= at + len {
        return Err(Asn1Error::MalformedValue);
    }
    let exp = &contents[at..at + len];
    if first & 3 == 3 {
        validate_integer_octets(exp)?;
    }
    let mut exponent = Exponent::binary(exp)?;
    exponent.mul(factor);
    exponent.adjust(false, usize::from((first >> 2) & 3));
    Ok((first & 0x40 != 0, &contents[at + len..], exponent))
}

fn decode(contents: &[u8]) -> Result<Asn1Real, Asn1Error> {
    let Some(first) = contents.first() else {
        return Ok(zero(false));
    };
    if *first >= 0x80 {
        let (negative, mantissa, exponent) = binary_parts(contents)?;
        if mantissa.iter().all(|b| *b == 0) {
            return Err(Asn1Error::MalformedValue);
        }
        binary(negative, mantissa, exponent)
    } else if matches!(*first, 1..=3) {
        let (negative, digits, exponent) = decimal_parts(contents)?;
        if digits.iter().all(|b| *b == b'0') {
            return Err(Asn1Error::MalformedValue);
        }
        decimal(negative, &digits, exponent)
    } else if (0x40..=0x43).contains(first) && contents.len() == 1 {
        Ok(Asn1Real {
            contents: contents.to_vec(),
        })
    } else {
        Err(Asn1Error::MalformedValue)
    }
}

impl From<f64> for Asn1Real {
    /// 精確轉成二進位 REAL；NaN payload 不保留。變動時間：依 IEEE 欄位與尾端零位元分支。
    fn from(value: f64) -> Self {
        let bits = value.to_bits();
        let negative = bits >> 63 != 0;
        let exp = ((bits >> 52) & 0x7FF) as i64;
        let fraction = bits & ((1_u64 << 52) - 1);
        if exp == 0x7FF {
            return Self {
                contents: vec![if fraction != 0 {
                    0x42
                } else if negative {
                    0x41
                } else {
                    0x40
                }],
            };
        }
        if exp == 0 && fraction == 0 {
            return zero(negative);
        }
        let (mantissa, exponent) = if exp == 0 {
            (fraction, -1074_i64)
        } else {
            (fraction | (1 << 52), exp - 1075)
        };
        Self::from_binary_parts(negative, &mantissa.to_be_bytes(), &exponent.to_be_bytes())
            .expect("f64 exponents fit REAL")
    }
}

fn binary_f64(negative: bool, mantissa: &[u8], exponent: Exponent) -> Result<f64, Asn1Error> {
    let precision = (mantissa.len() - 1) * 8 + (8 - mantissa[0].leading_zeros()) as usize;
    if precision > 53 {
        return Err(Asn1Error::InexactValue);
    }
    let e = exponent.to_i64()?;
    let top = e
        .checked_add(precision as i64 - 1)
        .ok_or(Asn1Error::InexactValue)?;
    if e < -1074 || top > 1023 {
        return Err(Asn1Error::InexactValue);
    }
    let n = mantissa.iter().fold(0_u64, |n, b| (n << 8) | u64::from(*b));
    let sign = u64::from(negative) << 63;
    let bits = if top >= -1022 {
        sign | (((top + 1023) as u64) << 52) | ((n << (53 - precision)) & ((1 << 52) - 1))
    } else {
        sign | (n << (e + 1074))
    };
    Ok(f64::from_bits(bits))
}

impl TryFrom<&Asn1Real> for f64 {
    type Error = Asn1Error;
    /// 精確轉成 f64；任何捨入、溢位或下溢都回傳 [`Asn1Error::InexactValue`]。
    /// 變動時間：依內容長度、底數與可表示範圍分支。
    fn try_from(value: &Asn1Real) -> Result<Self, Self::Error> {
        let contents = &value.contents;
        match contents.as_slice() {
            [] => Ok(0.0),
            [0x40] => Ok(f64::INFINITY),
            [0x41] => Ok(f64::NEG_INFINITY),
            [0x42] => Ok(f64::NAN),
            [0x43] => Ok(-0.0),
            [3, ..] => {
                let (negative, digits, exponent) = decimal_parts(contents)?;
                let e = exponent.to_i64()?;
                // 正規係數不以零結尾；精確 binary64 不需要超過這些保守界線。
                if !(-1074..=308).contains(&e) || digits.len() > 800 {
                    return Err(Asn1Error::InexactValue);
                }
                let mut n = Magnitude::decimal(&digits)?;
                if e < 0 {
                    for _ in 0..-e {
                        if n.divide(5) != 0 {
                            return Err(Asn1Error::InexactValue);
                        }
                    }
                } else {
                    for _ in 0..e {
                        n.mul(5);
                    }
                }
                let normalized =
                    Asn1Real::from_binary_parts(negative, &n.to_be(), &e.to_be_bytes())?;
                let (negative, mantissa, exponent) = binary_parts(&normalized.contents)?;
                binary_f64(negative, mantissa, exponent)
            }
            _ => {
                let (negative, mantissa, exponent) = binary_parts(contents)?;
                binary_f64(negative, mantissa, exponent)
            }
        }
    }
}
impl<'a> DecodeContent<'a> for Asn1Real {
    const TAG: &'static [u8] = TAG;
    /// 變動時間：接受 BER 各種 REAL 表示並正規化，保留原本的二進位或十進位底數。
    fn try_decode_content(value: &'a [u8], _: Depth) -> Result<Self, Asn1Error> {
        decode(value)
    }
}
impl Encode for Asn1Real {
    fn tag(&self) -> &[u8] {
        TAG
    }
    /// 常數時間：已保存正規內容。
    fn content_len(&self, _: EncodingType) -> usize {
        self.contents.len()
    }
    /// 變動時間：BER 與 DER 都寫出保存的正規內容。
    fn encode_content(&self, _: EncodingType, out: &mut [u8]) -> Result<usize, Asn1Error> {
        out[..self.contents.len()].copy_from_slice(&self.contents);
        Ok(self.contents.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decode;
    #[test]
    fn binary_real_vectors_normalize_base_scaling_and_even_mantissas() {
        for (input, expected) in [
            (&[0x80, 0xFF, 3][..], &[0x80, 0xFF, 3][..]),
            (&[0x80, 0xFE, 6], &[0x80, 0xFF, 3]),
            (&[0x90, 1, 3], &[0x80, 3, 3]),
            (&[0xAC, 0xFF, 3], &[0x80, 0xFF, 3]),
            (&[0xC0, 0, 0, 8], &[0xC0, 3, 1]),
        ] {
            let value = Asn1Real::try_decode_content(input, Depth::DEFAULT).unwrap();
            assert_eq!(value.as_bytes(), expected);
            assert_eq!(Asn1Real::from_der_bytes(expected), Ok(value));
        }
    }
    #[test]
    fn decimal_real_vectors_normalize_without_binary_rounding() {
        for input in [
            &b"\x01+00123"[..],
            &b"\x02123.00"[..],
            &b"\x03  +1,2300E+2"[..],
        ] {
            let value = Asn1Real::try_decode_content(input, Depth::DEFAULT).unwrap();
            assert_eq!(value.as_bytes(), b"\x03123.E+0");
            assert_eq!(f64::try_from(&value), Ok(123.0));
        }
        let tenth = Asn1Real::from_decimal_parts(false, "10", "-2").unwrap();
        assert_eq!(tenth.as_bytes(), b"\x031.E-1");
        assert_eq!(f64::try_from(&tenth), Err(Asn1Error::InexactValue));
        assert_eq!(
            f64::try_from(&Asn1Real::from_decimal_parts(false, "125", "-3").unwrap()),
            Ok(0.125)
        );
    }
    #[test]
    fn arbitrary_precision_mantissas_and_exponents_are_preserved_exactly() {
        let mut mantissa = vec![0xFF; 200];
        mantissa.push(1);
        let exponent = [1; 100];
        let value = Asn1Real::from_binary_parts(false, &mantissa, &exponent).unwrap();
        assert_eq!(&value.as_bytes()[..2], &[0x83, 100]);
        assert_eq!(
            Asn1Real::from_der_bytes(value.as_bytes()),
            Ok(value.clone())
        );
        assert_eq!(f64::try_from(&value), Err(Asn1Error::InexactValue));
        let exp = "99999999999999999999999999999999999999999999999999";
        let value = Asn1Real::from_decimal_parts(true, "1234500", exp).unwrap();
        assert_eq!(
            value.as_bytes(),
            b"\x03-12345.E100000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            Asn1Real::from_der_bytes(value.as_bytes()),
            Ok(value.clone())
        );
        assert_eq!(f64::try_from(&value), Err(Asn1Error::InexactValue));
    }
    #[test]
    fn f64_boundary_values_round_trip_without_losing_bits() {
        for value in [
            0.0,
            -0.0,
            1.0,
            -1.5,
            f64::MAX,
            f64::MIN_POSITIVE,
            f64::from_bits(1),
            f64::from_bits((1 << 52) - 1),
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            let real = Asn1Real::from(value);
            assert_eq!(f64::try_from(&real).unwrap().to_bits(), value.to_bits());
            let mut out = vec![0; real.encoded_len(EncodingType::Der)];
            let written = real.encode(EncodingType::Der, &mut out).unwrap();
            assert_eq!(
                Asn1Real::try_decode(&out, Depth::DEFAULT),
                Ok((written, real))
            );
        }
        assert!(f64::try_from(&Asn1Real::from(f64::NAN)).unwrap().is_nan());
        assert_ne!(Asn1Real::from(0.0), Asn1Real::from(-0.0));
    }
    #[test]
    fn f64_conversion_rejects_overflow_underflow_and_excess_precision() {
        for (mantissa, exp) in [
            (&[1][..], 1024_i64),
            (&[1][..], -1075),
            (&[0x20, 0, 0, 0, 0, 0, 1][..], 0),
        ] {
            let real = Asn1Real::from_binary_parts(false, mantissa, &exp.to_be_bytes()).unwrap();
            assert_eq!(f64::try_from(&real), Err(Asn1Error::InexactValue));
        }
    }
    #[test]
    fn malformed_real_contents_and_wrong_tags_are_rejected() {
        for contents in [
            &[0][..],
            &[0x44],
            &[0x40, 0],
            &[0xB0, 0, 1],
            &[0x83, 0, 1],
            &[0x80, 0],
            &[0x80, 0, 0],
            &[0x83, 2, 0, 0, 1],
            b"\x010",
            b"\x02.",
            b"\x03.E1",
            b"\x031.E",
            b"\x02NaN",
        ] {
            assert_eq!(
                Asn1Real::try_decode_content(contents, Depth::DEFAULT),
                Err(Asn1Error::MalformedValue),
                "{contents:?}"
            );
        }
        assert!(Asn1Real::from_der_bytes(&[0x80, 0, 2]).is_err());
        assert_eq!(
            Asn1Real::try_decode(&[2, 1, 0], Depth::DEFAULT),
            Err(Asn1Error::UnexpectedTag)
        );
    }
    #[test]
    fn exponent_carries_and_negative_adjustments_keep_their_sign() {
        let real = Asn1Real::from_binary_parts(false, &[2], &[0xFF]).unwrap();
        assert_eq!(real.as_bytes(), &[0x80, 0, 1]);
        let real = Asn1Real::from_binary_parts(false, &[2], &[0x7F]).unwrap();
        assert_eq!(real.as_bytes(), &[0x81, 0, 0x80, 1]);
        let real =
            Asn1Real::from_decimal_parts(false, "10", "-1000000000000000000000000000000").unwrap();
        assert_eq!(real.as_bytes(), b"\x031.E-999999999999999999999999999999");
    }
    #[test]
    fn decimal_grammar_requires_a_point_and_rejects_trailing_spaces_and_unsigned_zero_exponents() {
        for bytes in [
            &b"\x031E1"[..],
            b"\x031.E0",
            b"\x031.E-0",
            b"\x011 ",
            b"\x021. ",
            b"\x031.E+1 ",
        ] {
            assert!(
                Asn1Real::try_decode_content(bytes, Depth::DEFAULT).is_err(),
                "{bytes:?}"
            );
        }
        for bytes in [&b"\x03 .1e1"[..], b"\x031.E+0", b"\x021.", b"\x02.1"] {
            assert!(
                Asn1Real::try_decode_content(bytes, Depth::DEFAULT).is_ok(),
                "{bytes:?}"
            );
        }
    }
    #[test]
    fn every_f64_exponent_round_trips_with_representative_significands() {
        for exp in 0..=0x7FF_u64 {
            for frac in [0, 1, 3, 0x5555_5555_5555, (1 << 52) - 1] {
                for sign in [0, 1_u64 << 63] {
                    let bits = sign | (exp << 52) | frac;
                    let input = f64::from_bits(bits);
                    let encoded = Asn1Real::from(input);
                    let decoded = f64::try_from(&encoded).unwrap();
                    if input.is_nan() {
                        assert!(decoded.is_nan());
                    } else {
                        assert_eq!(decoded.to_bits(), bits);
                    }
                }
            }
        }
    }
    #[test]
    fn decimal_f64_extremes_convert_exactly_including_the_smallest_subnormal() {
        for value in [f64::from_bits(1), f64::MIN_POSITIVE, f64::MAX] {
            let text = alloc::format!("{value:.1074}");
            let mut content = vec![2];
            content.extend_from_slice(text.as_bytes());
            let real = Asn1Real::try_decode_content(&content, Depth::DEFAULT).unwrap();
            assert_eq!(f64::try_from(&real).unwrap().to_bits(), value.to_bits());
        }
    }
    #[test]
    fn binary_exponent_length_limits_are_checked_after_normalization() {
        let maximum = [0x7F; 255];
        let real = Asn1Real::from_binary_parts(false, &[1], &maximum).unwrap();
        assert_eq!(Asn1Real::from_der_bytes(real.as_bytes()), Ok(real));
        assert_eq!(
            Asn1Real::from_binary_parts(false, &[1], &[1; 256]),
            Err(Asn1Error::LengthOverflow)
        );
        let mut edge = [0xFF; 255];
        edge[0] = 0x7F;
        assert_eq!(
            Asn1Real::from_binary_parts(false, &[2], &edge),
            Err(Asn1Error::LengthOverflow)
        );
    }
}
