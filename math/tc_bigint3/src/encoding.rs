//! Conversion between little-endian limbs and little-endian external units.

use crate::{ConversionError, Limb, Word};

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

#[cfg(feature = "alloc")]
pub(crate) fn from_le_bytes(input: &[u8], signed: bool) -> Vec<Limb> {
    decode_units(
        input.iter().map(|value| *value as u64),
        input.len(),
        8,
        signed,
    )
}

#[cfg(feature = "alloc")]
pub(crate) fn from_le_u32(input: &[u32], signed: bool) -> Vec<Limb> {
    decode_units(
        input.iter().map(|value| *value as u64),
        input.len(),
        32,
        signed,
    )
}

#[cfg(feature = "alloc")]
pub(crate) fn from_le_u64(input: &[u64], signed: bool) -> Vec<Limb> {
    decode_units(input.iter().copied(), input.len(), 64, signed)
}

#[cfg(feature = "alloc")]
fn decode_units(
    units: impl Iterator<Item = u64>,
    unit_len: usize,
    unit_bits: usize,
    signed: bool,
) -> Vec<Limb> {
    if unit_len == 0 {
        return Vec::new();
    }

    let total_bits = unit_len * unit_bits;
    let word_bits = Word::BITS as usize;
    let mut words = vec![Limb(0); total_bits.div_ceil(word_bits)];
    let mut last = 0_u64;

    for (unit_index, unit) in units.enumerate() {
        last = unit;
        let bit = unit_index * unit_bits;
        let word_index = bit / word_bits;
        let shift = bit % word_bits;
        words[word_index].0 |= (unit as Word) << shift;
        if shift + unit_bits > word_bits {
            words[word_index + 1].0 |= (unit >> (word_bits - shift)) as Word;
        }
    }

    let negative = signed && last >> (unit_bits - 1) != 0;
    let used_high_bits = total_bits % word_bits;
    if negative && used_high_bits != 0 {
        let last_word = words.last_mut().expect("non-empty input has a word");
        last_word.0 |= Word::MAX << used_high_bits;
    }

    if signed {
        normalize_signed(&mut words);
    } else {
        crate::arithmetic::normalize(&mut words);
    }
    words
}

#[cfg(feature = "alloc")]
pub(crate) fn unsigned_to_le_bytes(words: &[Limb]) -> Vec<u8> {
    encode_unsigned(words, 8)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

#[cfg(feature = "alloc")]
pub(crate) fn unsigned_to_le_u32(words: &[Limb]) -> Vec<u32> {
    encode_unsigned(words, 32)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

#[cfg(feature = "alloc")]
pub(crate) fn unsigned_to_le_u64(words: &[Limb]) -> Vec<u64> {
    encode_unsigned(words, 64)
}

#[cfg(feature = "alloc")]
pub(crate) fn signed_to_le_bytes(words: &[Limb]) -> Vec<u8> {
    encode_signed(words, 8)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

#[cfg(feature = "alloc")]
pub(crate) fn signed_to_le_u32(words: &[Limb]) -> Vec<u32> {
    encode_signed(words, 32)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

#[cfg(feature = "alloc")]
pub(crate) fn signed_to_le_u64(words: &[Limb]) -> Vec<u64> {
    encode_signed(words, 64)
}

#[cfg(feature = "alloc")]
pub(crate) fn write_unsigned_le_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_unsigned_units(words, 8, output, |value| value as u8)
}

#[cfg(feature = "alloc")]
pub(crate) fn write_unsigned_le_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_unsigned_units(words, 32, output, |value| value as u32)
}

#[cfg(feature = "alloc")]
pub(crate) fn write_unsigned_le_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_unsigned_units(words, 64, output, |value| value)
}

#[cfg(feature = "alloc")]
pub(crate) fn write_signed_le_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 8, output, |value| value as u8)
}

#[cfg(feature = "alloc")]
pub(crate) fn write_signed_le_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 32, output, |value| value as u32)
}

#[cfg(feature = "alloc")]
pub(crate) fn write_signed_le_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 64, output, |value| value)
}

#[cfg(feature = "alloc")]
fn write_unsigned_units<T>(
    words: &[Limb],
    unit_bits: usize,
    output: &mut [T],
    convert: impl Fn(u64) -> T,
) -> Result<usize, ConversionError> {
    let len = crate::arithmetic::bit_len(words).div_ceil(unit_bits).max(1);
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    for (index, item) in output[..len].iter_mut().enumerate() {
        *item = convert(extract_unit(words, index, unit_bits, 0));
    }
    Ok(len)
}

#[cfg(feature = "alloc")]
fn write_signed_units<T>(
    words: &[Limb],
    unit_bits: usize,
    output: &mut [T],
    convert: impl Fn(u64) -> T,
) -> Result<usize, ConversionError> {
    let negative = is_negative(words);
    let extension = if negative { Word::MAX } else { 0 };
    let mut len = if words.is_empty() {
        1
    } else {
        (words.len() * Word::BITS as usize).div_ceil(unit_bits)
    };
    let unit_max = unit_mask(unit_bits);
    while len > 1 {
        let high = extract_unit(words, len - 1, unit_bits, extension);
        let next = extract_unit(words, len - 2, unit_bits, extension);
        let next_negative = next >> (unit_bits - 1) != 0;
        if (high == 0 && !next_negative) || (high == unit_max && next_negative) {
            len -= 1;
        } else {
            break;
        }
    }
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    for (index, item) in output[..len].iter_mut().enumerate() {
        *item = convert(extract_unit(words, index, unit_bits, extension));
    }
    Ok(len)
}

#[cfg(feature = "alloc")]
fn encode_unsigned(words: &[Limb], unit_bits: usize) -> Vec<u64> {
    let bits = crate::arithmetic::bit_len(words);
    let len = bits.div_ceil(unit_bits).max(1);
    (0..len)
        .map(|index| extract_unit(words, index, unit_bits, 0))
        .collect()
}

#[cfg(feature = "alloc")]
fn encode_signed(words: &[Limb], unit_bits: usize) -> Vec<u64> {
    if words.is_empty() {
        return vec![0];
    }

    let negative = is_negative(words);
    let extension = if negative { Word::MAX } else { 0 };
    let word_bits = Word::BITS as usize;
    let mut result: Vec<u64> = (0..(words.len() * word_bits).div_ceil(unit_bits))
        .map(|index| extract_unit(words, index, unit_bits, extension))
        .collect();
    let unit_max = unit_mask(unit_bits);

    while result.len() > 1 {
        let high = result[result.len() - 1];
        let next = result[result.len() - 2];
        let next_negative = next >> (unit_bits - 1) != 0;
        if (high == 0 && !next_negative) || (high == unit_max && next_negative) {
            result.pop();
        } else {
            break;
        }
    }
    result
}

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
    let mut result = [Limb(extension_word); N];

    for bit in 0..unit_len * unit_bits {
        let bit_value = unit(bit / unit_bits) >> (bit % unit_bits) & 1;
        if bit >= capacity_bits {
            if bit_value != extension_bit {
                return Err(ConversionError::InputTooLarge);
            }
            continue;
        }

        let word = &mut result[bit / Word::BITS as usize].0;
        let mask = (1 as Word) << (bit % Word::BITS as usize);
        if bit_value == 0 {
            *word &= !mask;
        } else {
            *word |= mask;
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
    let len = N * Word::BITS as usize / 8;
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    let extension = signed_extension(words, signed);
    for (index, item) in output[..len].iter_mut().enumerate() {
        *item = extract_unit(words, index, 8, extension) as u8;
    }
    Ok(len)
}

pub(crate) fn write_fixed_le_u32<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    let len = (N * Word::BITS as usize).div_ceil(32);
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    let extension = signed_extension(words, signed);
    for (index, item) in output[..len].iter_mut().enumerate() {
        *item = extract_unit(words, index, 32, extension) as u32;
    }
    Ok(len)
}

pub(crate) fn write_fixed_le_u64<const N: usize>(
    words: &[Limb; N],
    signed: bool,
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    let len = (N * Word::BITS as usize).div_ceil(64);
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    let extension = signed_extension(words, signed);
    for (index, item) in output[..len].iter_mut().enumerate() {
        *item = extract_unit(words, index, 64, extension);
    }
    Ok(len)
}

fn extract_unit(words: &[Limb], index: usize, unit_bits: usize, extension: Word) -> u64 {
    let word_bits = Word::BITS as usize;
    let bit = index * unit_bits;
    let word_index = bit / word_bits;
    let shift = bit % word_bits;
    let low = word_to_u64(words.get(word_index).map_or(extension, |word| word.0));
    let mut result = low >> shift;
    if shift + unit_bits > word_bits {
        let high = word_to_u64(words.get(word_index + 1).map_or(extension, |word| word.0));
        result |= high << (word_bits - shift);
    }
    result & unit_mask(unit_bits)
}

fn unit_mask(unit_bits: usize) -> u64 {
    if unit_bits == 64 {
        u64::MAX
    } else {
        (1_u64 << unit_bits) - 1
    }
}

#[cfg(target_pointer_width = "64")]
fn word_to_u64(value: Word) -> u64 {
    value
}

#[cfg(not(target_pointer_width = "64"))]
fn word_to_u64(value: Word) -> u64 {
    u64::from(value)
}

#[cfg(feature = "alloc")]
pub(crate) fn normalize_signed(words: &mut Vec<Limb>) {
    while words.len() > 1 {
        let high = words[words.len() - 1].0;
        let next = words[words.len() - 2].0;
        let next_negative = next >> (Word::BITS - 1) != 0;
        if (high == 0 && !next_negative) || (high == Word::MAX && next_negative) {
            words.pop();
        } else {
            break;
        }
    }
    if *words == [Limb(0)] {
        words.clear();
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn is_negative(words: &[Limb]) -> bool {
    words
        .last()
        .is_some_and(|word| word.0 >> (Word::BITS - 1) != 0)
}

fn signed_extension<const N: usize>(words: &[Limb; N], signed: bool) -> Word {
    if signed && crate::arithmetic::fixed_is_negative(words) {
        Word::MAX
    } else {
        0
    }
}

fn fixed_is_negative<const N: usize>(words: &[Limb; N]) -> bool {
    words
        .last()
        .is_some_and(|word| word.0 >> (Word::BITS - 1) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_decoders_cover_bytes_u32_u64_and_sign_extension() {
        let from_bytes = fixed_from_le_bytes::<2>(&[0x88, 0x77, 0x66, 0x55], false).unwrap();
        let from_u32 = fixed_from_le_u32::<2>(&[0x5566_7788], false).unwrap();
        let from_u64 = fixed_from_le_u64::<2>(&[0x5566_7788], false).unwrap();
        assert_eq!(from_bytes, from_u32);
        assert_eq!(from_u32, from_u64);

        let negative = fixed_from_le_bytes::<1>(&[0xff], true).unwrap();
        assert_eq!(negative, [Limb(Word::MAX)]);
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
            Ok([Limb(Word::MAX)])
        );
        assert_eq!(
            fixed_from_le_bytes::<1>(&[0x80], true),
            Ok([Limb(Word::MAX - 0x7f)])
        );
    }

    #[test]
    fn fixed_writers_cover_each_unit_and_buffer_error() {
        let words = [Limb(0x1122_3344_5566_7788_u64 as Word)];
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
        assert_eq!(words64[0] as Word, words[0].0);

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

    #[test]
    fn extraction_masks_units_and_uses_extension_words() {
        assert_eq!(unit_mask(8), 0xff);
        assert_eq!(unit_mask(64), u64::MAX);
        assert_eq!(word_to_u64(7), 7);
        assert_eq!(extract_unit(&[Limb(0x1234)], 0, 8, 0), 0x34);
        assert_eq!(extract_unit(&[], 0, 8, Word::MAX), 0xff);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_decoders_and_unsigned_encoders_cover_empty_and_cross_unit_values() {
        assert!(from_le_bytes(&[], false).is_empty());
        let bytes = [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let words = from_le_bytes(&bytes, false);
        assert_eq!(from_le_u32(&[0x5566_7788, 0x1122_3344], false), words);
        assert_eq!(from_le_u64(&[0x1122_3344_5566_7788], false), words);
        assert_eq!(unsigned_to_le_bytes(&words), bytes);
        assert_eq!(unsigned_to_le_u32(&words), [0x5566_7788, 0x1122_3344]);
        assert_eq!(unsigned_to_le_u64(&words), [0x1122_3344_5566_7788]);
        assert_eq!(unsigned_to_le_bytes(&[]), [0]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_signed_encoders_are_canonical_for_positive_and_negative_values() {
        let minus_two = from_le_bytes(&[0xfe], true);
        assert!(is_negative(&minus_two));
        assert_eq!(signed_to_le_bytes(&minus_two), [0xfe]);
        assert_eq!(signed_to_le_u32(&minus_two), [u32::MAX - 1]);
        assert_eq!(signed_to_le_u64(&minus_two), [u64::MAX - 1]);
        assert_eq!(signed_to_le_bytes(&[]), [0]);

        let positive = from_le_bytes(&[0x80, 0x00], true);
        assert!(!is_negative(&positive));
        assert_eq!(signed_to_le_bytes(&positive), [0x80, 0x00]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn signed_normalization_removes_only_redundant_extension_limbs() {
        let mut positive = vec![Limb(1), Limb(0)];
        normalize_signed(&mut positive);
        assert_eq!(positive, [Limb(1)]);

        let mut negative = vec![Limb(Word::MAX - 1), Limb(Word::MAX)];
        normalize_signed(&mut negative);
        assert_eq!(negative, [Limb(Word::MAX - 1)]);

        let mut zero = vec![Limb(0)];
        normalize_signed(&mut zero);
        assert!(zero.is_empty());
    }
}
