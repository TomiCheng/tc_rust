//! Encoding and decoding for the allocating, variable-length representations.

use alloc::{vec, vec::Vec};

use super::shared::{
    Endian, extract_unit, is_negative, magnitude_len, unit_mask, unsigned_bit_len,
    write_magnitude_units,
};
use crate::{ConversionError, Limb, Word};

pub(crate) fn from_le_bytes(input: &[u8], signed: bool) -> Vec<Limb> {
    decode_units(
        input.iter().map(|value| *value as u64),
        input.len(),
        8,
        signed,
    )
}

pub(crate) fn from_le_u32(input: &[u32], signed: bool) -> Vec<Limb> {
    decode_units(
        input.iter().map(|value| *value as u64),
        input.len(),
        32,
        signed,
    )
}

pub(crate) fn from_le_u64(input: &[u64], signed: bool) -> Vec<Limb> {
    decode_units(input.iter().copied(), input.len(), 64, signed)
}

pub(crate) fn from_be_bytes(input: &[u8], signed: bool) -> Vec<Limb> {
    decode_units(
        input.iter().rev().map(|value| *value as u64),
        input.len(),
        8,
        signed,
    )
}

pub(crate) fn from_be_u32(input: &[u32], signed: bool) -> Vec<Limb> {
    decode_units(
        input.iter().rev().map(|value| *value as u64),
        input.len(),
        32,
        signed,
    )
}

pub(crate) fn from_be_u64(input: &[u64], signed: bool) -> Vec<Limb> {
    decode_units(input.iter().rev().copied(), input.len(), 64, signed)
}

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
    let mut words = vec![Limb::new(0); total_bits.div_ceil(word_bits)];
    let mut last = 0_u64;

    for (unit_index, unit) in units.enumerate() {
        last = unit;
        let bit = unit_index * unit_bits;
        let word_index = bit / word_bits;
        let shift = bit % word_bits;
        words[word_index] = Limb::new(words[word_index].to_word() | ((unit as Word) << shift));
        if shift + unit_bits > word_bits {
            words[word_index + 1] = Limb::new(
                words[word_index + 1].to_word() | ((unit >> (word_bits - shift)) as Word),
            );
        }
    }

    let negative = signed && last >> (unit_bits - 1) != 0;
    let used_high_bits = total_bits % word_bits;
    if negative && used_high_bits != 0 {
        let last_word = words.last_mut().expect("non-empty input has a word");
        *last_word = Limb::new(last_word.to_word() | (Word::MAX << used_high_bits));
    }

    if signed {
        normalize_signed(&mut words);
    } else {
        crate::arithmetic::normalize(&mut words);
    }
    words
}

pub(crate) fn unsigned_to_le_bytes(words: &[Limb]) -> Vec<u8> {
    encode_magnitude(words, 8, false, Endian::Little)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

pub(crate) fn unsigned_to_le_u32(words: &[Limb]) -> Vec<u32> {
    encode_magnitude(words, 32, false, Endian::Little)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

pub(crate) fn unsigned_to_le_u64(words: &[Limb]) -> Vec<u64> {
    encode_magnitude(words, 64, false, Endian::Little)
}

pub(crate) fn unsigned_to_be_bytes(words: &[Limb]) -> Vec<u8> {
    encode_magnitude(words, 8, false, Endian::Big)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

pub(crate) fn unsigned_to_be_u32(words: &[Limb]) -> Vec<u32> {
    encode_magnitude(words, 32, false, Endian::Big)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

pub(crate) fn unsigned_to_be_u64(words: &[Limb]) -> Vec<u64> {
    encode_magnitude(words, 64, false, Endian::Big)
}

pub(crate) fn magnitude_to_le_bytes(words: &[Limb]) -> Vec<u8> {
    encode_magnitude(words, 8, true, Endian::Little)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

pub(crate) fn magnitude_to_le_u32(words: &[Limb]) -> Vec<u32> {
    encode_magnitude(words, 32, true, Endian::Little)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

pub(crate) fn magnitude_to_le_u64(words: &[Limb]) -> Vec<u64> {
    encode_magnitude(words, 64, true, Endian::Little)
}

pub(crate) fn magnitude_to_be_bytes(words: &[Limb]) -> Vec<u8> {
    encode_magnitude(words, 8, true, Endian::Big)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

pub(crate) fn magnitude_to_be_u32(words: &[Limb]) -> Vec<u32> {
    encode_magnitude(words, 32, true, Endian::Big)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

pub(crate) fn magnitude_to_be_u64(words: &[Limb]) -> Vec<u64> {
    encode_magnitude(words, 64, true, Endian::Big)
}

pub(crate) fn signed_to_le_bytes(words: &[Limb]) -> Vec<u8> {
    encode_signed(words, 8, Endian::Little)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

pub(crate) fn signed_to_le_u32(words: &[Limb]) -> Vec<u32> {
    encode_signed(words, 32, Endian::Little)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

pub(crate) fn signed_to_le_u64(words: &[Limb]) -> Vec<u64> {
    encode_signed(words, 64, Endian::Little)
}

pub(crate) fn signed_to_be_bytes(words: &[Limb]) -> Vec<u8> {
    encode_signed(words, 8, Endian::Big)
        .into_iter()
        .map(|value| value as u8)
        .collect()
}

pub(crate) fn signed_to_be_u32(words: &[Limb]) -> Vec<u32> {
    encode_signed(words, 32, Endian::Big)
        .into_iter()
        .map(|value| value as u32)
        .collect()
}

pub(crate) fn signed_to_be_u64(words: &[Limb]) -> Vec<u64> {
    encode_signed(words, 64, Endian::Big)
}

pub(crate) fn write_unsigned_le_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 8, false, Endian::Little, output, |value| value as u8)
}

pub(crate) fn write_unsigned_le_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 32, false, Endian::Little, output, |value| {
        value as u32
    })
}

pub(crate) fn write_unsigned_le_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 64, false, Endian::Little, output, |value| value)
}

pub(crate) fn write_unsigned_be_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 8, false, Endian::Big, output, |value| value as u8)
}

pub(crate) fn write_unsigned_be_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 32, false, Endian::Big, output, |value| value as u32)
}

pub(crate) fn write_unsigned_be_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 64, false, Endian::Big, output, |value| value)
}

pub(crate) fn write_magnitude_le_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 8, true, Endian::Little, output, |value| value as u8)
}

pub(crate) fn write_magnitude_le_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 32, true, Endian::Little, output, |value| {
        value as u32
    })
}

pub(crate) fn write_magnitude_le_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 64, true, Endian::Little, output, |value| value)
}

pub(crate) fn write_magnitude_be_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 8, true, Endian::Big, output, |value| value as u8)
}

pub(crate) fn write_magnitude_be_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 32, true, Endian::Big, output, |value| value as u32)
}

pub(crate) fn write_magnitude_be_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_magnitude_units(words, 64, true, Endian::Big, output, |value| value)
}

pub(crate) fn write_signed_le_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 8, Endian::Little, output, |value| value as u8)
}

pub(crate) fn write_signed_le_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 32, Endian::Little, output, |value| value as u32)
}

pub(crate) fn write_signed_le_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 64, Endian::Little, output, |value| value)
}

pub(crate) fn write_signed_be_bytes(
    words: &[Limb],
    output: &mut [u8],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 8, Endian::Big, output, |value| value as u8)
}

pub(crate) fn write_signed_be_u32(
    words: &[Limb],
    output: &mut [u32],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 32, Endian::Big, output, |value| value as u32)
}

pub(crate) fn write_signed_be_u64(
    words: &[Limb],
    output: &mut [u64],
) -> Result<usize, ConversionError> {
    write_signed_units(words, 64, Endian::Big, output, |value| value)
}

fn encode_magnitude(
    words: &[Limb],
    unit_bits: usize,
    signed_source: bool,
    endian: Endian,
) -> Vec<u64> {
    let mut result = vec![0; magnitude_len(words, unit_bits, signed_source)];
    write_magnitude_units(
        words,
        unit_bits,
        signed_source,
        endian,
        &mut result,
        |value| value,
    )
    .expect("output has the exact magnitude length");
    result
}

fn encode_signed(words: &[Limb], unit_bits: usize, endian: Endian) -> Vec<u64> {
    let mut result = vec![0; signed_len(words, unit_bits)];
    write_signed_units(words, unit_bits, endian, &mut result, |value| value)
        .expect("output has the exact signed length");
    result
}

pub(crate) fn unsigned_len(words: &[Limb], unit_bits: usize) -> usize {
    unsigned_bit_len(words).div_ceil(unit_bits).max(1)
}

pub(crate) fn signed_len(words: &[Limb], unit_bits: usize) -> usize {
    if words.is_empty() {
        return 1;
    }

    let negative = is_negative(words);
    let extension = if negative { Word::MAX } else { 0 };
    let mut len = (words.len() * Word::BITS as usize).div_ceil(unit_bits);
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
    len
}

fn write_signed_units<T>(
    words: &[Limb],
    unit_bits: usize,
    endian: Endian,
    output: &mut [T],
    convert: impl Fn(u64) -> T,
) -> Result<usize, ConversionError> {
    let len = signed_len(words, unit_bits);
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }
    let extension = if is_negative(words) { Word::MAX } else { 0 };
    for source in 0..len {
        let target = match endian {
            Endian::Little => source,
            Endian::Big => len - 1 - source,
        };
        output[target] = convert(extract_unit(words, source, unit_bits, extension));
    }
    Ok(len)
}

pub(crate) fn normalize_signed(words: &mut Vec<Limb>) {
    while words.len() > 1 {
        let high = words[words.len() - 1].to_word();
        let next = words[words.len() - 2].to_word();
        let next_negative = next >> (Word::BITS - 1) != 0;
        if (high == 0 && !next_negative) || (high == Word::MAX && next_negative) {
            words.pop();
        } else {
            break;
        }
    }
    if *words == [Limb::new(0)] {
        words.clear();
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{Limb, Word};

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

    #[test]
    fn signed_normalization_removes_only_redundant_extension_limbs() {
        let mut positive = vec![Limb::new(1), Limb::new(0)];
        normalize_signed(&mut positive);
        assert_eq!(positive, [Limb::new(1)]);

        let mut negative = vec![Limb::new(Word::MAX - 1), Limb::new(Word::MAX)];
        normalize_signed(&mut negative);
        assert_eq!(negative, [Limb::new(Word::MAX - 1)]);

        let mut zero = vec![Limb::new(0)];
        normalize_signed(&mut zero);
        assert!(zero.is_empty());
    }
}
