//! Unit extraction and length arithmetic shared by both representations.

use crate::{ConversionError, Limb, Word};

#[derive(Clone, Copy)]
pub(super) enum Endian {
    Little,
    Big,
}

pub(crate) fn magnitude_len(words: &[Limb], unit_bits: usize, signed_source: bool) -> usize {
    magnitude_bit_len(words, signed_source)
        .div_ceil(unit_bits)
        .max(1)
}

pub(super) fn magnitude_bit_len(words: &[Limb], signed_source: bool) -> usize {
    if !signed_source || !is_negative(words) {
        return unsigned_bit_len(words);
    }

    let mut carry = true;
    let mut highest = None;
    for (index, word) in words.iter().enumerate() {
        let (magnitude, overflow) = (!word.to_word()).overflowing_add(Word::from(carry));
        carry = overflow;
        if magnitude != 0 {
            highest = Some((index, magnitude));
        }
    }
    highest.map_or(0, |(index, word)| {
        index * Word::BITS as usize + (Word::BITS - word.leading_zeros()) as usize
    })
}

pub(super) fn unsigned_bit_len(words: &[Limb]) -> usize {
    words
        .iter()
        .rposition(|word| word.to_word() != 0)
        .map_or(0, |index| {
            index * Word::BITS as usize
                + (Word::BITS - words[index].to_word().leading_zeros()) as usize
        })
}

pub(super) fn write_magnitude_units<T>(
    words: &[Limb],
    unit_bits: usize,
    signed_source: bool,
    endian: Endian,
    output: &mut [T],
    convert: impl Fn(u64) -> T,
) -> Result<usize, ConversionError> {
    let len = magnitude_len(words, unit_bits, signed_source);
    if output.len() < len {
        return Err(ConversionError::BufferTooSmall);
    }

    let negative = signed_source && is_negative(words);
    let extension = if negative { Word::MAX } else { 0 };
    let mask = unit_mask(unit_bits);
    let mut carry = u64::from(negative);
    for source in 0..len {
        let raw = extract_unit(words, source, unit_bits, extension);
        let value = if negative {
            let value = ((!raw) & mask).wrapping_add(carry) & mask;
            carry = u64::from(carry != 0 && raw == 0);
            value
        } else {
            raw
        };
        let target = match endian {
            Endian::Little => source,
            Endian::Big => len - 1 - source,
        };
        output[target] = convert(value);
    }
    Ok(len)
}

pub(super) fn extract_unit(words: &[Limb], index: usize, unit_bits: usize, extension: Word) -> u64 {
    let word_bits = Word::BITS as usize;
    let bit = index * unit_bits;
    let word_index = bit / word_bits;
    let shift = bit % word_bits;
    let low = word_to_u64(
        words
            .get(word_index)
            .map_or(extension, |word| word.to_word()),
    );
    let mut result = low >> shift;
    if shift + unit_bits > word_bits {
        let high = word_to_u64(
            words
                .get(word_index + 1)
                .map_or(extension, |word| word.to_word()),
        );
        result |= high << (word_bits - shift);
    }
    result & unit_mask(unit_bits)
}

pub(super) fn unit_mask(unit_bits: usize) -> u64 {
    if unit_bits == 64 {
        u64::MAX
    } else {
        (1_u64 << unit_bits) - 1
    }
}

#[cfg(target_pointer_width = "64")]
pub(super) fn word_to_u64(value: Word) -> u64 {
    value
}

#[cfg(not(target_pointer_width = "64"))]
pub(super) fn word_to_u64(value: Word) -> u64 {
    u64::from(value)
}

pub(crate) fn is_negative(words: &[Limb]) -> bool {
    words
        .last()
        .is_some_and(|word| word.to_word() >> (Word::BITS - 1) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Limb, Word};

    #[test]
    fn extraction_masks_units_and_uses_extension_words() {
        assert_eq!(unit_mask(8), 0xff);
        assert_eq!(unit_mask(64), u64::MAX);
        assert_eq!(word_to_u64(7), 7);
        assert_eq!(extract_unit(&[Limb::new(0x1234)], 0, 8, 0), 0x34);
        assert_eq!(extract_unit(&[], 0, 8, Word::MAX), 0xff);
    }
}
