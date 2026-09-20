use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::integer_octets::{minimal_signed, validate_integer_octets};
use crate::{
    Asn1Error, Decode, DecodeContent, DecodeInner, DecodingContext, Encode, EncodingOptions, Tagged,
};

/// An INTEGER of any size, kept as its two's-complement content octets.
///
/// # Examples
///
/// ```
/// use tc_asn1::Asn1Integer;
///
/// let serial = Asn1Integer::from_unsigned_bytes(&[0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x15, 0x4b]);
/// assert_eq!(serial.to_string(), "288230376151782731");
/// assert_eq!(format!("{serial:x}"), "40000000001154b");
/// assert_eq!(format!("{:#X}", Asn1Integer::from(-255)), "-0xFF");
/// assert_eq!(Asn1Integer::from(-256).to_string(), "-256");
/// assert_eq!(format!("{} {:x}", Asn1Integer::from(0), Asn1Integer::from(0)), "0 0");
/// assert_eq!(format!("{:>6}|{:04x}", Asn1Integer::from(42), Asn1Integer::from(42)), "    42|002a");
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Asn1Integer {
    value: Vec<u8>,
}

impl Asn1Integer {
    pub const TAG: &'static [u8] = super::tag::INTEGER;

    pub fn from_der_bytes(bytes: &[u8]) -> Result<Self, Asn1Error> {
        validate_integer_octets(bytes)?;
        Ok(Self {
            value: bytes.to_vec(),
        })
    }

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

    fn from_signed_bytes(twos_complement: &[u8]) -> Self {
        Self {
            value: minimal_signed(twos_complement).to_vec(),
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

    /// The absolute value, big-endian without leading zeros; empty for zero.
    fn magnitude(&self) -> Vec<u8> {
        let mut magnitude = self.value.clone();
        if self.is_negative() {
            // two's complement: invert, then add one from the low end
            let mut carry = true;
            for byte in magnitude.iter_mut().rev() {
                *byte = !*byte;
                if carry {
                    let (sum, overflow) = byte.overflowing_add(1);
                    *byte = sum;
                    carry = overflow;
                }
            }
        }
        let start = magnitude
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(magnitude.len());
        magnitude.drain(..start);
        magnitude
    }

    /// The magnitude in decimal, by long division; `"0"` for zero.
    fn decimal_digits(&self) -> String {
        let mut magnitude = self.magnitude();
        let mut digits = Vec::new();
        while !magnitude.is_empty() {
            let mut remainder = 0u16;
            for byte in &mut magnitude {
                let current = (remainder << 8) | u16::from(*byte);
                *byte = (current / 10) as u8;
                remainder = current % 10;
            }
            digits.push(b'0' + remainder as u8);
            if magnitude[0] == 0 {
                magnitude.remove(0);
            }
        }
        if digits.is_empty() {
            digits.push(b'0');
        }
        digits.reverse();
        String::from_utf8(digits).expect("ASCII digits")
    }

    /// The magnitude in hex without a leading zero digit; `"0"` for zero.
    fn hex_digits(&self, upper: bool) -> String {
        let magnitude = self.magnitude();
        let mut digits = String::with_capacity(magnitude.len() * 2);
        for (i, byte) in magnitude.iter().enumerate() {
            let (high, low) = (byte >> 4, byte & 0x0F);
            if i > 0 || high != 0 {
                digits.push(hex_digit(high, upper));
            }
            digits.push(hex_digit(low, upper));
        }
        if digits.is_empty() {
            digits.push('0');
        }
        digits
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

fn hex_digit(nibble: u8, upper: bool) -> char {
    let digit = match nibble {
        0..=9 => b'0' + nibble,
        _ if upper => b'A' + nibble - 10,
        _ => b'a' + nibble - 10,
    };
    char::from(digit)
}

/// Decimal, with a leading `-` when negative. Width, fill and `+` are
/// honoured as for the primitive integers.
impl fmt::Display for Asn1Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(!self.is_negative(), "", &self.decimal_digits())
    }
}

/// The magnitude in lowercase hex, `-` first when negative, `0x` with `#`.
impl fmt::LowerHex for Asn1Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(!self.is_negative(), "0x", &self.hex_digits(false))
    }
}

/// The magnitude in uppercase hex, `-` first when negative, `0x` with `#`.
impl fmt::UpperHex for Asn1Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad_integral(!self.is_negative(), "0x", &self.hex_digits(true))
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

impl DecodeInner for Asn1Integer {
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
}

impl Decode for Asn1Integer {}
impl Tagged for Asn1Integer {
    const TAG: &'static [u8] = Self::TAG;
}

impl DecodeContent for Asn1Integer {
    fn decode_content(value: &[u8], context: &mut DecodingContext) -> Result<Self, Asn1Error> {
        context.options().check_content_len(value.len())?;
        Self::from_der_bytes(value)
    }
}

impl crate::EncodeContent for Asn1Integer {
    fn content_len(&self, _: &EncodingOptions) -> usize {
        self.value.len()
    }

    fn encode_content(&self, _: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        let out = out
            .get_mut(..self.value.len())
            .ok_or(Asn1Error::BufferTooSmall)?;
        out.copy_from_slice(&self.value);
        Ok(self.value.len())
    }
}

impl crate::EncodeTagged for Asn1Integer {}

impl Encode for Asn1Integer {
    fn encoded_len(&self, rules: &EncodingOptions) -> usize {
        crate::EncodeTagged::encoded_len_tagged(self, Self::TAG, rules)
    }

    fn encode(&self, rules: &EncodingOptions, out: &mut [u8]) -> Result<usize, Asn1Error> {
        crate::EncodeTagged::encode_tagged(self, Self::TAG, rules, out)
    }
}
