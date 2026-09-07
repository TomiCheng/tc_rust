//! Radix parsing into variable-length limbs.

use alloc::vec::Vec;

use crate::ParseBigIntError;
use crate::limb::slice::{add_small, mul_small, normalize};
use crate::{Limb, Word};

pub(crate) fn parse_unsigned(
    value: &str,
    radix: u32,
) -> Result<(bool, Vec<Limb>), ParseBigIntError> {
    if !(2..=36).contains(&radix) {
        return Err(ParseBigIntError::InvalidRadix);
    }

    let (negative, digits) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if digits.is_empty() {
        return Err(ParseBigIntError::InvalidDigit);
    }

    let mut words = Vec::new();
    for byte in digits.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'z' => u32::from(byte - b'a') + 10,
            b'A'..=b'Z' => u32::from(byte - b'A') + 10,
            _ => return Err(ParseBigIntError::InvalidDigit),
        };
        if digit >= radix {
            return Err(ParseBigIntError::InvalidDigit);
        }
        mul_small(&mut words, radix as Word);
        add_small(&mut words, digit as Word);
    }

    normalize(&mut words);
    Ok((negative && !words.is_empty(), words))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::ParseBigIntError;

    #[test]
    fn parses_signs_radixes_and_rejects_invalid_input() {
        assert_eq!(parse_unsigned("+FF", 16), Ok((false, vec![Limb::new(255)])));
        assert_eq!(parse_unsigned("-10", 10), Ok((true, vec![Limb::new(10)])));
        assert_eq!(parse_unsigned("-0", 10), Ok((false, vec![])));
        assert_eq!(parse_unsigned("?", 10), Err(ParseBigIntError::InvalidDigit));
    }
}
