//! Parsing and formatting for [`FixedBigInt`].

use core::fmt;
use core::str::FromStr;

use crate::traits::Num;
use crate::{FixedBigInt, FixedBigUint, ParseBigIntError};

impl<const N: usize> FixedBigInt<N> {
    /// Parses a signed value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let (negative, digits) = if let Some(digits) = value.strip_prefix('-') {
            (true, digits)
        } else {
            (false, value.strip_prefix('+').unwrap_or(value))
        };
        let magnitude = FixedBigUint::<N>::from_str_radix(digits, radix)?;
        Self::from_sign_magnitude(negative, magnitude.into_limbs())
            .ok_or(ParseBigIntError::Overflow)
    }

    /// Formats this value in radix `2..=36`.
    #[cfg(feature = "alloc")]
    pub fn to_str_radix(&self, radix: u32) -> alloc::string::String {
        crate::BigInt::from(*self).to_str_radix(radix)
    }
}

impl<const N: usize> FromStr for FixedBigInt<N> {
    type Err = ParseBigIntError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}

impl<const N: usize> Num for FixedBigInt<N> {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        Self::from_str_radix(value, radix)
    }
}

impl<const N: usize> fmt::Display for FixedBigInt<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::format::fmt_fixed(&self.magnitude(), self.is_negative(), 10, false, "", output)
    }
}

impl<const N: usize> fmt::Debug for FixedBigInt<N> {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_fixed_int_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl<const N: usize> fmt::$trait for FixedBigInt<N> {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                crate::format::fmt_fixed(
                    &self.magnitude(),
                    self.is_negative(),
                    $radix,
                    $uppercase,
                    $prefix,
                    output,
                )
            }
        }
    };
}

impl_fixed_int_format!(Binary, 2, false, "0b");
impl_fixed_int_format!(Octal, 8, false, "0o");
impl_fixed_int_format!(LowerHex, 16, false, "0x");
impl_fixed_int_format!(UpperHex, 16, true, "0x");

#[cfg(feature = "alloc")]
impl<const N: usize> crate::ToStrRadix for FixedBigInt<N> {
    fn to_str_radix(&self, radix: u32) -> alloc::string::String {
        FixedBigInt::<N>::to_str_radix(self, radix)
    }
}
