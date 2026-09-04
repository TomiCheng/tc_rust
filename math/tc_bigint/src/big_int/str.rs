//! Parsing and formatting for [`BigInt`].

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

use crate::traits::Num;
use crate::{BigInt, BigUint, ParseBigIntError, arithmetic};

impl BigInt {
    /// Parses a signed value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let (negative, magnitude) = arithmetic::parse_unsigned(value, radix)?;
        Ok(Self::from_sign_magnitude(negative, magnitude))
    }

    /// Formats the value in radix `2..=36`.
    pub fn to_str_radix(&self, radix: u32) -> String {
        let (negative, magnitude) = self.sign_magnitude();
        let mut output = BigUint::from_limbs(magnitude).to_str_radix(radix);
        if negative {
            output.insert(0, '-');
        }
        output
    }

    fn fmt_radix(
        &self,
        radix: u32,
        uppercase: bool,
        prefix: &'static str,
        output: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let (negative, magnitude) = self.sign_magnitude();
        let mut digits = BigUint::from_limbs(magnitude).to_str_radix(radix);
        if uppercase {
            digits.make_ascii_uppercase();
        }
        output.pad_integral(
            !negative,
            if output.alternate() { prefix } else { "" },
            &digits,
        )
    }
}

impl FromStr for BigInt {
    type Err = ParseBigIntError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}

impl Num for BigInt {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        BigInt::from_str_radix(value, radix)
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_radix(10, false, "", output)
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_big_int_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl fmt::$trait for BigInt {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.fmt_radix($radix, $uppercase, $prefix, output)
            }
        }
    };
}

impl_big_int_format!(Binary, 2, false, "0b");
impl_big_int_format!(Octal, 8, false, "0o");
impl_big_int_format!(LowerHex, 16, false, "0x");
impl_big_int_format!(UpperHex, 16, true, "0x");
