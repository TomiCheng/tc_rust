//! Parsing and formatting for [`FixedBigUint`].

use core::fmt;
use core::str::FromStr;

use crate::traits::Num;
use crate::{FixedBigUint, ParseBigIntError, Word};

impl<const N: usize> FixedBigUint<N> {
    /// Parses an unsigned value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        if !(2..=36).contains(&radix) {
            return Err(ParseBigIntError::InvalidRadix);
        }
        let digits = value.strip_prefix('+').unwrap_or(value);
        if digits.starts_with('-') {
            return Err(ParseBigIntError::NegativeUnsigned);
        }
        if digits.is_empty() {
            return Err(ParseBigIntError::InvalidDigit);
        }

        let mut result = Self::zero();
        for byte in digits.bytes() {
            let digit = decode_digit(byte, radix)?;
            result = result
                .checked_mul_word(radix as Word)
                .and_then(|value| value.checked_add_word(digit as Word))
                .ok_or(ParseBigIntError::Overflow)?;
        }
        Ok(result)
    }

    /// Formats this value in radix `2..=36`.
    #[cfg(feature = "alloc")]
    pub fn to_str_radix(&self, radix: u32) -> alloc::string::String {
        crate::BigUint::from(*self).to_str_radix(radix)
    }
}

fn decode_digit(byte: u8, radix: u32) -> Result<u32, ParseBigIntError> {
    let digit = match byte {
        b'0'..=b'9' => u32::from(byte - b'0'),
        b'a'..=b'z' => u32::from(byte - b'a') + 10,
        b'A'..=b'Z' => u32::from(byte - b'A') + 10,
        _ => return Err(ParseBigIntError::InvalidDigit),
    };
    (digit < radix)
        .then_some(digit)
        .ok_or(ParseBigIntError::InvalidDigit)
}

impl<const N: usize> FromStr for FixedBigUint<N> {
    type Err = ParseBigIntError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}

impl<const N: usize> Num for FixedBigUint<N> {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        Self::from_str_radix(value, radix)
    }
}

impl<const N: usize> fmt::Display for FixedBigUint<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::format::fmt_fixed(self.limbs.as_limbs(), false, 10, false, "", output)
    }
}

impl<const N: usize> fmt::Debug for FixedBigUint<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_fixed_uint_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl<const N: usize> fmt::$trait for FixedBigUint<N> {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::format::fmt_fixed(
                    self.limbs.as_limbs(),
                    false,
                    $radix,
                    $uppercase,
                    $prefix,
                    output,
                )
            }
        }
    };
}

impl_fixed_uint_format!(Binary, 2, false, "0b");
impl_fixed_uint_format!(Octal, 8, false, "0o");
impl_fixed_uint_format!(LowerHex, 16, false, "0x");
impl_fixed_uint_format!(UpperHex, 16, true, "0x");
