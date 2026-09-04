//! Allocation-free formatting helpers for fixed-width integers.

use core::fmt::{self, Alignment, Write};

use crate::{Limb, WideWord, Word};

pub(crate) fn fmt_fixed<const N: usize>(
    limbs: &[Limb; N],
    negative: bool,
    radix: u32,
    uppercase: bool,
    prefix: &'static str,
    output: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    debug_assert!((2..=36).contains(&radix));
    let (chunk_base, digits_per_chunk) = chunk_base(radix as Word);
    let digits = digit_count(*limbs, radix as Word, chunk_base, digits_per_chunk);
    let sign = if negative {
        Some('-')
    } else if output.sign_plus() {
        Some('+')
    } else {
        None
    };
    let prefix = if output.alternate() { prefix } else { "" };
    let content_width = digits + prefix.len() + usize::from(sign.is_some());
    let padding = output.width().unwrap_or(0).saturating_sub(content_width);

    if output.sign_aware_zero_pad() {
        write_sign_and_prefix(output, sign, prefix)?;
        write_fill(output, '0', padding)?;
        return write_digits(
            *limbs,
            radix as Word,
            chunk_base,
            digits_per_chunk,
            uppercase,
            output,
        );
    }

    let (left, right) = match output.align().unwrap_or(Alignment::Right) {
        Alignment::Left => (0, padding),
        Alignment::Right => (padding, 0),
        Alignment::Center => (padding / 2, padding - padding / 2),
    };
    write_fill(output, output.fill(), left)?;
    write_sign_and_prefix(output, sign, prefix)?;
    write_digits(
        *limbs,
        radix as Word,
        chunk_base,
        digits_per_chunk,
        uppercase,
        output,
    )?;
    write_fill(output, output.fill(), right)
}

fn write_sign_and_prefix(
    output: &mut fmt::Formatter<'_>,
    sign: Option<char>,
    prefix: &str,
) -> fmt::Result {
    if let Some(sign) = sign {
        output.write_char(sign)?;
    }
    output.write_str(prefix)
}

fn write_fill(output: &mut fmt::Formatter<'_>, fill: char, count: usize) -> fmt::Result {
    for _ in 0..count {
        output.write_char(fill)?;
    }
    Ok(())
}

fn chunk_base(radix: Word) -> (Word, usize) {
    let mut base = radix;
    let mut digits = 1;
    while let Some(next) = base.checked_mul(radix) {
        base = next;
        digits += 1;
    }
    (base, digits)
}

fn digit_count<const N: usize>(
    mut value: [Limb; N],
    radix: Word,
    chunk_base: Word,
    digits_per_chunk: usize,
) -> usize {
    if is_zero(&value) {
        return 1;
    }

    let mut chunks = 0;
    let most_significant = loop {
        let (quotient, remainder) = div_rem_word(value, chunk_base);
        chunks += 1;
        if is_zero(&quotient) {
            break remainder;
        }
        value = quotient;
    };

    (chunks - 1) * digits_per_chunk + word_digit_count(most_significant, radix)
}

fn write_digits<const N: usize>(
    value: [Limb; N],
    radix: Word,
    chunk_base: Word,
    digits_per_chunk: usize,
    uppercase: bool,
    output: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    if is_zero(&value) {
        return output.write_char('0');
    }
    write_chunks(
        value,
        radix,
        chunk_base,
        digits_per_chunk,
        uppercase,
        output,
    )
}

fn write_chunks<const N: usize>(
    value: [Limb; N],
    radix: Word,
    chunk_base: Word,
    digits_per_chunk: usize,
    uppercase: bool,
    output: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let (quotient, remainder) = div_rem_word(value, chunk_base);
    if is_zero(&quotient) {
        write_word(remainder, radix, 0, uppercase, output)
    } else {
        write_chunks(
            quotient,
            radix,
            chunk_base,
            digits_per_chunk,
            uppercase,
            output,
        )?;
        write_word(remainder, radix, digits_per_chunk, uppercase, output)
    }
}

fn write_word(
    mut value: Word,
    radix: Word,
    minimum_digits: usize,
    uppercase: bool,
    output: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let mut digits = [0_u8; 64];
    let mut len = 0;
    while value != 0 {
        digits[len] = (value % radix) as u8;
        len += 1;
        value /= radix;
    }
    let width = len.max(minimum_digits).max(1);
    for index in (0..width).rev() {
        let digit = digits.get(index).copied().unwrap_or(0);
        output.write_char(match digit {
            0..=9 => char::from(b'0' + digit),
            _ if uppercase => char::from(b'A' + digit - 10),
            _ => char::from(b'a' + digit - 10),
        })?;
    }
    Ok(())
}

fn word_digit_count(mut value: Word, radix: Word) -> usize {
    let mut count = 1;
    while value >= radix {
        value /= radix;
        count += 1;
    }
    count
}

fn div_rem_word<const N: usize>(mut value: [Limb; N], divisor: Word) -> ([Limb; N], Word) {
    let mut remainder = 0 as Word;
    for limb in value.iter_mut().rev() {
        let wide = ((remainder as WideWord) << Word::BITS) | limb.0 as WideWord;
        *limb = Limb((wide / divisor as WideWord) as Word);
        remainder = (wide % divisor as WideWord) as Word;
    }
    (value, remainder)
}

fn is_zero(limbs: &[Limb]) -> bool {
    limbs.iter().all(|limb| limb.0 == 0)
}

#[cfg(test)]
mod tests {
    use crate::{FixedBigInt, FixedBigUint};
    use std::string::ToString;

    #[test]
    fn fixed_formatting_is_numeric_and_honors_standard_flags() {
        type U = FixedBigUint<4>;
        type I = FixedBigInt<4>;
        let unsigned = U::from(u128::MAX);
        let signed = I::from(-0x2a_i8);

        assert_eq!(std::format!("{unsigned}"), u128::MAX.to_string());
        assert_eq!(std::format!("{unsigned:?}"), u128::MAX.to_string());
        assert_eq!(std::format!("{unsigned:x}"), std::format!("{:x}", u128::MAX));
        assert_eq!(std::format!("{unsigned:X}"), std::format!("{:X}", u128::MAX));
        assert_eq!(std::format!("{unsigned:o}"), std::format!("{:o}", u128::MAX));
        assert_eq!(std::format!("{unsigned:b}"), std::format!("{:b}", u128::MAX));
        assert_eq!(std::format!("{:#010x}", U::from(0x2a_u8)), "0x0000002a");
        assert_eq!(std::format!("{signed}"), "-42");
        assert_eq!(std::format!("{signed:?}"), "-42");
        assert_eq!(std::format!("{signed:+#010x}"), "-0x000002a");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn all_integer_types_parse_decimal_and_format_every_supported_base() {
        use core::str::FromStr;

        use crate::{BigInt, BigUint};

        assert_eq!(FixedBigUint::<2>::from_str("255"), Ok(FixedBigUint::from(255_u16)));
        assert_eq!(FixedBigInt::<2>::from_str("-255"), Ok(FixedBigInt::from(-255_i16)));
        assert_eq!(FixedBigUint::<2>::from(255_u16).to_str_radix(16), "ff");
        assert_eq!(FixedBigInt::<2>::from(-255_i16).to_str_radix(16), "-ff");

        let unsigned = BigUint::from(u128::MAX);
        let signed = BigInt::from(-255_i16);
        assert_eq!(std::format!("{unsigned:#X}"), std::format!("{:#X}", u128::MAX));
        assert_eq!(std::format!("{signed:b}"), "-11111111");
        assert_eq!(std::format!("{unsigned:?}"), u128::MAX.to_string());
        assert_eq!(std::format!("{signed:?}"), "-255");
    }
}
