//! Encoding and decoding for the fixed-width representations, without allocation.

use super::shared::{Endian, extract_unit, write_magnitude_units};
use crate::{ConversionError, Limb, Word};

pub(crate) fn fixed_from_le_bytes<const N: usize>(
    input: &[u8],
    signed: bool,
) -> Result<[Limb; N], ConversionError> {
    decode_fixed(input.len(), 8, signed, |index| input[index] as u64)
}

pub(crate) fn fixed_from_le_u32<const N: usize>(
    input: &[u32],
    signed: bool,
) -> Result<[Limb; N], ConversionError> {
    decode_fixed(input.len(), 32, signed, |index| input[index] as u64)
}

pub(crate) fn fixed_from_le_u64<const N: usize>(
    input: &[u64],
    signed: bool,
) -> Result<[Limb; N], ConversionError> {
    decode_fixed(input.len(), 64, signed, |index| input[index])
}

pub(crate) fn fixed_from_be_bytes<const N: usize>(
    input: &[u8],
    signed: bool,
) -> Result<[Limb; N], ConversionError> {
    decode_fixed(input.len(), 8, signed, |index| {
        input[input.len() - 1 - index] as u64
    })
}

pub(crate) fn fixed_from_be_u32<const N: usize>(
    input: &[u32],
    signed: bool,
) -> Result<[Limb; N], ConversionError> {
    decode_fixed(input.len(), 32, signed, |index| {
        input[input.len() - 1 - index] as u64
    })
}

pub(crate) fn fixed_from_be_u64<const N: usize>(
    input: &[u64],
    signed: bool,
) -> Result<[Limb; N], ConversionError> {
    decode_fixed(input.len(), 64, signed, |index| {
        input[input.len() - 1 - index]
    })
}

fn decode_fixed<const N: usize>(
    unit_len: usize,
    unit_bits: usize,
    signed: bool,
    unit: impl Fn(usize) -> u64,
) -> Result<[Limb; N], ConversionError> {
    let negative = signed && unit_len != 0 && unit(unit_len - 1) >> (unit_bits - 1) != 0;
    let extension_bit = u64::from(negative);
    let extension_word = if negative { Word::MAX } else { 0 };
    let capacity_bits = N * Word::BITS as usize;
    let mut result = [Limb::new(extension_word); N];

    for bit in 0..unit_len * unit_bits {
        let bit_value = unit(bit / unit_bits) >> (bit % unit_bits) & 1;
        if bit >= capacity_bits {
            if bit_value != extension_bit {
                return Err(ConversionError::InputTooLarge);
            }
            continue;
        }

        let word = &mut result[bit / Word::BITS as usize];
        let mask = (1 as Word) << (bit % Word::BITS as usize);
        if bit_value == 0 {
            *word = Limb::new(word.to_word() & !mask);
        } else {
            *word = Limb::new(word.to_word() | mask);
        }
    }

    if N == 0 {
        return if unit_len == 0 || (0..unit_len).all(|index| unit(index) == 0) {
            Ok(result)
        } else {
            Err(ConversionError::InputTooLarge)
        };
    }
    if signed && fixed_is_negative(&result) != negative {
        return Err(ConversionError::InputTooLarge);
    }
    Ok(result)
}

pub(crate) fn write_fixed_le_bytes<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_fixed_units(words, signed, 8, Endian::Little, output, |value| {
        value as u8
    })
}

pub(crate) fn write_fixed_le_u32<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_fixed_units(words, signed, 32, Endian::Little, output, |value| {
        value as u32
    })
}

pub(crate) fn write_fixed_le_u64<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_fixed_units(words, signed, 64, Endian::Little, output, |value| value)
}

pub(crate) fn write_fixed_be_bytes<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_fixed_units(words, signed, 8, Endian::Big, output, |value| value as u8)
}

pub(crate) fn write_fixed_be_u32<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_fixed_units(words, signed, 32, Endian::Big, output, |value| value as u32)
}

pub(crate) fn write_fixed_be_u64<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_fixed_units(words, signed, 64, Endian::Big, output, |value| value)
}

pub(crate) fn write_fixed_magnitude_le_bytes<const N: usize>(
    words: &[Limb; N],
    signed_source: bool,
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 8, signed_source, Endian::Little, output, |value| {
        value as u8
    })
}

pub(crate) fn write_fixed_magnitude_le_u32<const N: usize>(
    words: &[Limb; N],
    signed_source: bool,
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 32, signed_source, Endian::Little, output, |value| {
        value as u32
    })
}

pub(crate) fn write_fixed_magnitude_le_u64<const N: usize>(
    words: &[Limb; N],
    signed_source: bool,
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 64, signed_source, Endian::Little, output, |value| {
        value
    })
}

pub(crate) fn write_fixed_magnitude_be_bytes<const N: usize>(
    words: &[Limb; N],
    signed_source: bool,
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 8, signed_source, Endian::Big, output, |value| {
        value as u8
    })
}

pub(crate) fn write_fixed_magnitude_be_u32<const N: usize>(
    words: &[Limb; N],
    signed_source: bool,
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 32, signed_source, Endian::Big, output, |value| {
        value as u32
    })
}

pub(crate) fn write_fixed_magnitude_be_u64<const N: usize>(
    words: &[Limb; N],
    signed_source: bool,
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 64, signed_source, Endian::Big, output, |value| value)
}

fn write_fixed_units<const N: usize, T>(
    words: &[Limb; N],
    signed: bool,
    unit_bits: usize,
    endian: Endian,
    output: &mut [T],
    convert: impl Fn(u64) -> T,
) -> Result<usize, ConversionError> {
    let len = match unit_bits {
        8 => N * Word::BITS as usize / 8,
        32 => (N * Word::BITS as usize).div_ceil(32),
        64 => (N * Word::BITS as usize).div_ceil(64),
        _ => unreachable!("external units are u8, u32, or u64"),
    };
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    let extension = signed_extension(words, signed);
    for source in 0..len {
        let target = match endian {
            Endian::Little => source,
            Endian::Big => len - 1 - source,
        };
        output[target] = convert(extract_unit(words, source, unit_bits, extension));
    }
    Ok(len)
}

pub(super) fn signed_extension<const N: usize>(words: &[Limb; N], signed: bool) -> Word {
    if signed && crate::FixedBigInt::is_negative_limbs(words) {
        Word::MAX
    } else {
        0
    }
}

pub(super) fn fixed_is_negative<const N: usize>(words: &[Limb; N]) -> bool {
    words
        .last()
        .is_some_and(|word| word.to_word() >> (Word::BITS - 1) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConversionError, Limb, Word};

    #[test]
    fn fixed_decoders_cover_bytes_u32_u64_and_sign_extension() {
        let from_bytes = fixed_from_le_bytes::<2>(&[0x88, 0x77, 0x66, 0x55], false).unwrap();
        let from_u32 = fixed_from_le_u32::<2>(&[0x5566_7788], false).unwrap();
        let from_u64 = fixed_from_le_u64::<2>(&[0x5566_7788], false).unwrap();
        assert_eq!(from_bytes, from_u32);
        assert_eq!(from_u32, from_u64);

        let negative = fixed_from_le_bytes::<1>(&[0xff], true).unwrap();
        assert_eq!(negative, [Limb::new(Word::MAX)]);
        assert!(fixed_is_negative(&negative));
        assert_eq!(signed_extension(&negative, true), Word::MAX);
        assert_eq!(signed_extension(&negative, false), 0);
    }

    #[test]
    fn fixed_decoder_rejects_values_outside_the_destination_precision() {
        assert_eq!(
            fixed_from_le_bytes::<0>(&[1], false),
            Err(ConversionError::InputTooLarge)
        );
        assert_eq!(fixed_from_le_bytes::<0>(&[], false), Ok([]));
        assert_eq!(fixed_from_le_u32::<0>(&[0], false), Ok([]));
        assert_eq!(
            fixed_from_le_u64::<0>(&[1], false),
            Err(ConversionError::InputTooLarge)
        );

        let unsigned_overflow = [0_u8; (Word::BITS / 8) as usize + 1];
        let mut unsigned_overflow = unsigned_overflow;
        *unsigned_overflow.last_mut().unwrap() = 1;
        assert_eq!(
            fixed_from_le_bytes::<1>(&unsigned_overflow, false),
            Err(ConversionError::InputTooLarge)
        );

        let signed_positive_overflow = [0xff_u8; (Word::BITS / 8) as usize];
        assert_eq!(
            fixed_from_le_bytes::<1>(&signed_positive_overflow, false),
            Ok([Limb::new(Word::MAX)])
        );
        assert_eq!(
            fixed_from_le_bytes::<1>(&[0x80], true),
            Ok([Limb::new(Word::MAX - 0x7f)])
        );
    }

    #[test]
    fn fixed_writers_cover_each_unit_and_buffer_error() {
        let words = [Limb::new(0x1122_3344_5566_7788_u64 as Word)];
        let mut bytes = [0_u8; (Word::BITS / 8) as usize];
        let mut words32 = [0_u32; (Word::BITS / 32) as usize];
        let mut words64 = [0_u64; 1];

        assert_eq!(
            write_fixed_le_bytes(&words, false, &mut bytes),
            Ok(bytes.len())
        );
        assert_eq!(bytes[0], 0x88);
        assert_eq!(
            write_fixed_le_u32(&words, false, &mut words32),
            Ok(words32.len())
        );
        assert_eq!(words32[0], 0x5566_7788);
        assert_eq!(write_fixed_le_u64(&words, false, &mut words64), Ok(1));
        assert_eq!(words64[0] as Word, words[0].to_word());

        assert_eq!(
            write_fixed_le_bytes(&words, false, &mut []),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            write_fixed_le_u32(&words, false, &mut []),
            Err(ConversionError::BufferTooSmall)
        );
        assert_eq!(
            write_fixed_le_u64(&words, false, &mut []),
            Err(ConversionError::BufferTooSmall)
        );
    }
}
