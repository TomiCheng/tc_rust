//! ASN.1 REAL: binary and decimal finite values kept exactly, plus the
//! infinities, NaN and the signed zeros.
//!
//! The value stores the canonical DER contents; there is no arithmetic and no
//! big-integer crate. Finite values are not limited to f64 precision; binary
//! exponents respect the wire format's 255-octet limit. All parsing,
//! normalization and conversion is variable time and only for public values.

use alloc::{vec, vec::Vec};

use super::{
    integer_octets::validate_integer_octets,
    real_number::{Exponent, Magnitude},
};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, DecodingOptions, Encode,
    EncodeContent, EncodeTagged, EncodingOptions,
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Real {
    contents: Vec<u8>,
}

impl Asn1Real {
    pub const TAG: &'static [u8] = super::tag::REAL;

    pub fn from_binary_parts(
        negative: bool,
        mantissa: &[u8],
        exponent: &[u8],
    ) -> Result<Self, Asn1Error> {
        binary(negative, mantissa, Exponent::binary(exponent)?)
    }

    pub fn from_decimal_parts(
        negative: bool,
        mantissa: &str,
        exponent: &str,
    ) -> Result<Self, Asn1Error> {
        decimal(negative, mantissa.as_bytes(), Exponent::decimal(exponent)?)
    }

    pub fn from_der_bytes(contents: &[u8]) -> Result<Self, Asn1Error> {
        let value = decode(contents)?;
        if value.contents != contents {
            return Err(Asn1Error::MalformedValue);
        }
        Ok(value)
    }
    /// The canonical DER contents.
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
    /// Exact conversion to a binary REAL; NaN payloads are dropped.
    /// Variable time: branches on the IEEE fields and trailing zero bits.
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
    /// Exact conversion to f64; any rounding, overflow or underflow is
    /// [`Asn1Error::InexactValue`]. Variable time: branches on the contents
    /// length, base and representable range.
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
                // A normalized mantissa has no trailing zeros; an exact binary64
                // never needs more than these conservative bounds.
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
impl DecodeInner for Asn1Real {
    fn decode_inner(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content(element.value(), context)?;
        Ok((element.total_len(), value))
    }

    fn decode_inner_der(
        buff: &[u8],
        context: &mut DecodingContext,
    ) -> Result<(usize, Self), Asn1Error> {
        let element = crate::Asn1Ref::parse_der(buff, context)?;
        if element.tag() != Self::TAG {
            return Err(Asn1Error::UnexpectedTag);
        }
        let value = Self::decode_content_der(element.value(), context)?;
        Ok((element.total_len(), value))
    }
}

impl Decode for Asn1Real {
    fn decode(buff: &[u8], options: &DecodingOptions) -> Result<(usize, Self), Asn1Error> {
        Self::decode_inner(buff, &mut DecodingContext::new(options.clone()))
    }
}

impl DecodeContent for Asn1Real {
    /// Accepts every BER form of REAL and normalizes it, keeping the original
    /// base (binary or decimal). Variable time: branches on the contents.
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        decode(value)
    }

    /// DER contents are the normalized form (X.690 §11.3), which is what the
    /// value stores: anything else is `NotDer`.
    fn decode_content_der(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        let decoded = Self::decode_content(value, context)?;
        if decoded.contents != value {
            return Err(Asn1Error::NotDer);
        }
        Ok(decoded)
    }
}

impl EncodeContent for Asn1Real {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.contents.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.contents.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.contents);
        Ok(self.contents.len())
    }
}

impl EncodeTagged for Asn1Real {}

impl Encode for Asn1Real {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        self.encoded_len_tagged(Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        self.encode_tagged(Self::TAG, rules, out)
    }
}

