//! Parsing and formatting for [`BigUint`].

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::traits::Num;
use crate::{BigUint, ParseBigIntError, Word, arithmetic};

impl BigUint {
    /// Parses an unsigned value in radix `2..=36`.
    pub fn from_str_radix(value: &str, radix: u32) -> Result<Self, ParseBigIntError> {
        let (negative, limbs) = arithmetic::parse_unsigned(value, radix)?;
        if negative {
            return Err(ParseBigIntError::NegativeUnsigned);
        }
        Ok(Self::from_limbs(limbs))
    }

    /// Formats the value in radix `2..=36`.
    pub fn to_str_radix(&self, radix: u32) -> String {
        assert!((2..=36).contains(&radix), "radix must be in 2..=36");
        if self.is_zero() {
            return String::from("0");
        }

        let mut words = self.limbs.clone();
        let mut digits = Vec::new();
        while !words.is_empty() {
            let digit = arithmetic::div_rem_small(&mut words, radix as Word) as u8;
            digits.push(if digit < 10 {
                b'0' + digit
            } else {
                b'a' + digit - 10
            });
        }
        digits.reverse();
        String::from_utf8(digits).expect("radix digits are ASCII")
    }

    fn fmt_radix(
        &self,
        radix: u32,
        uppercase: bool,
        prefix: &'static str,
        output: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let mut digits = self.to_str_radix(radix);
        if uppercase {
            digits.make_ascii_uppercase();
        }
        output.pad_integral(true, if output.alternate() { prefix } else { "" }, &digits)
    }
}

impl FromStr for BigUint {
    type Err = ParseBigIntError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_str_radix(value, 10)
    }
}

impl Num for BigUint {
    type FromStrRadixErr = ParseBigIntError;
    fn from_str_radix(value: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
        BigUint::from_str_radix(value, radix)
    }
}

impl fmt::Display for BigUint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_radix(10, false, "", output)
    }
}

impl fmt::Debug for BigUint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, output)
    }
}

macro_rules! impl_big_uint_format {
    ($trait:ident, $radix:expr, $uppercase:expr, $prefix:expr) => {
        impl fmt::$trait for BigUint {
            fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.fmt_radix($radix, $uppercase, $prefix, output)
            }
        }
    };
}

impl_big_uint_format!(Binary, 2, false, "0b");
impl_big_uint_format!(Octal, 8, false, "0o");
impl_big_uint_format!(LowerHex, 16, false, "0x");
impl_big_uint_format!(UpperHex, 16, true, "0x");
