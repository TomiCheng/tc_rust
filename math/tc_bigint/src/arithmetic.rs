//! Internal arithmetic over little-endian unsigned limbs.

#[cfg(any(feature = "alloc", test))]
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use crate::WideWord;
#[cfg(any(feature = "alloc", test))]
use crate::{Limb, Word};

#[cfg(feature = "alloc")]
use crate::ParseBigIntError;

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

// The crossover is intentionally expressed in limbs. On the common 64-bit
// target, 32 limbs starts Karatsuba at 2048-bit RSA-sized operands while
// keeping 256-bit ECC arithmetic on the schoolbook path.
#[cfg(feature = "alloc")]
const KARATSUBA_THRESHOLD: usize = 32;

#[cfg(feature = "alloc")]
pub(crate) fn normalize(words: &mut Vec<Limb>) {
    while words.last() == Some(&Limb::new(0)) {
        words.pop();
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn cmp(lhs: &[Limb], rhs: &[Limb]) -> Ordering {
    let lhs_len = significant_len(lhs);
    let rhs_len = significant_len(rhs);
    match lhs_len.cmp(&rhs_len) {
        Ordering::Equal => lhs[..lhs_len].iter().rev().cmp(rhs[..rhs_len].iter().rev()),
        ordering => ordering,
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn significant_len(words: &[Limb]) -> usize {
    words
        .iter()
        .rposition(|word| word.to_word() != 0)
        .map_or(0, |index| index + 1)
}

#[cfg(feature = "alloc")]
pub(crate) fn mul(lhs: &[Limb], rhs: &[Limb]) -> Vec<Limb> {
    let lhs = &lhs[..significant_len(lhs)];
    let rhs = &rhs[..significant_len(rhs)];
    if lhs.is_empty() || rhs.is_empty() {
        return Vec::new();
    }

    if let Some(shift) = power_of_two_shift(lhs) {
        return shl(rhs, shift);
    }
    if let Some(shift) = power_of_two_shift(rhs) {
        return shl(lhs, shift);
    }

    karatsuba_mul(lhs, rhs)
}

#[cfg(feature = "alloc")]
fn schoolbook_mul(lhs: &[Limb], rhs: &[Limb]) -> Vec<Limb> {
    if lhs.is_empty() || rhs.is_empty() {
        return Vec::new();
    }

    let mut result = vec![Limb::new(0); lhs.len() + rhs.len()];
    for (left_index, left) in lhs.iter().enumerate() {
        if left.to_word() == 0 {
            continue;
        }
        let mut carry = 0 as Word;
        for (right_index, right) in rhs.iter().enumerate() {
            let index = left_index + right_index;
            let wide = left.to_word() as WideWord * right.to_word() as WideWord
                + result[index].to_word() as WideWord
                + carry as WideWord;
            result[index] = Limb::new(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        result[left_index + rhs.len()] = Limb::new(carry);
    }

    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
fn karatsuba_mul(lhs: &[Limb], rhs: &[Limb]) -> Vec<Limb> {
    let lhs = &lhs[..significant_len(lhs)];
    let rhs = &rhs[..significant_len(rhs)];
    let (short, long) = if lhs.len() <= rhs.len() {
        (lhs, rhs)
    } else {
        (rhs, lhs)
    };

    if short.len() < KARATSUBA_THRESHOLD {
        return schoolbook_mul(short, long);
    }
    if short.len() < long.len() / 2 {
        return karatsuba_uneven_mul(short, long);
    }

    let split = long.len() / 2;
    let (short_low, short_high) = short.split_at(split);
    let (long_low, long_high) = long.split_at(split);

    let low_product = karatsuba_mul(short_low, long_low);
    let high_product = karatsuba_mul(short_high, long_high);
    let short_sum = add_magnitudes(short_low, short_high);
    let long_sum = add_magnitudes(long_low, long_high);
    let mut middle_product = karatsuba_mul(&short_sum, &long_sum);
    sub_assign_magnitude(&mut middle_product, &low_product);
    sub_assign_magnitude(&mut middle_product, &high_product);

    let mut result = low_product;
    result.reserve(short.len() + long.len() - result.len());
    add_shifted_assign(&mut result, &middle_product, split);
    add_shifted_assign(&mut result, &high_product, split * 2);
    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
fn karatsuba_uneven_mul(short: &[Limb], long: &[Limb]) -> Vec<Limb> {
    debug_assert!(!short.is_empty() && short.len() < long.len() / 2);
    let mut result = vec![Limb::new(0); short.len() + long.len()];
    for (chunk_index, chunk) in long.chunks(short.len()).enumerate() {
        let product = karatsuba_mul(short, chunk);
        add_shifted_assign(&mut result, &product, chunk_index * short.len());
    }
    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
fn add_magnitudes(lhs: &[Limb], rhs: &[Limb]) -> Vec<Limb> {
    let len = lhs.len().max(rhs.len());
    let mut result = Vec::with_capacity(len + 1);
    let mut carry = Limb::new(0);
    for index in 0..len {
        let left = lhs.get(index).copied().unwrap_or_default();
        let right = rhs.get(index).copied().unwrap_or_default();
        let (sum, next_carry) = left.carrying_add(right, carry);
        result.push(sum);
        carry = next_carry;
    }
    if carry.to_word() != 0 {
        result.push(carry);
    }
    result
}

#[cfg(feature = "alloc")]
fn sub_assign_magnitude(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    debug_assert!(cmp(lhs, rhs) != Ordering::Less);
    let mut borrow = Limb::new(0);
    for (index, left) in lhs.iter_mut().enumerate() {
        let right = rhs.get(index).copied().unwrap_or_default();
        (*left, borrow) = left.borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb::new(0));
    normalize(lhs);
}

#[cfg(feature = "alloc")]
fn add_shifted_assign(lhs: &mut Vec<Limb>, rhs: &[Limb], shift: usize) {
    if rhs.is_empty() {
        return;
    }
    let required_len = shift + rhs.len();
    if lhs.len() < required_len {
        lhs.resize(required_len, Limb::new(0));
    }

    let mut carry = Limb::new(0);
    for (index, right) in rhs.iter().copied().enumerate() {
        let output = shift + index;
        (lhs[output], carry) = lhs[output].carrying_add(right, carry);
    }
    let mut output = required_len;
    while carry.to_word() != 0 {
        if output == lhs.len() {
            lhs.push(carry);
            break;
        }
        (lhs[output], carry) = lhs[output].carrying_add(Limb::new(0), carry);
        output += 1;
    }
}

/// Squares a magnitude using symmetric schoolbook multiplication below the
/// Karatsuba threshold and the recursive multiplication path above it.
#[cfg(feature = "alloc")]
pub(crate) fn square(words: &[Limb]) -> Vec<Limb> {
    let len = significant_len(words);
    if len == 0 {
        return Vec::new();
    }
    let words = &words[..len];
    if len < KARATSUBA_THRESHOLD {
        schoolbook_square(words)
    } else {
        karatsuba_mul(words, words)
    }
}

#[cfg(feature = "alloc")]
fn schoolbook_square(words: &[Limb]) -> Vec<Limb> {
    let len = words.len();

    let mut result = vec![Limb::new(0); 2 * len];
    for left in 0..len {
        let diagonal = words[left].to_word() as WideWord * words[left].to_word() as WideWord;
        add_wide_at(&mut result, left * 2, diagonal);
        for right in left + 1..len {
            let product = words[left].to_word() as WideWord * words[right].to_word() as WideWord;
            add_wide_at(&mut result, left + right, product);
            add_wide_at(&mut result, left + right, product);
        }
    }

    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
fn add_wide_at(words: &mut [Limb], index: usize, value: WideWord) {
    let low = Limb::new(value as Word);
    let high = Limb::new((value >> Word::BITS) as Word);
    let (word, carry) = words[index].carrying_add(low, Limb::new(0));
    words[index] = word;
    let (word, mut carry) = words[index + 1].carrying_add(high, carry);
    words[index + 1] = word;

    let mut index = index + 2;
    while carry.to_word() != 0 && index < words.len() {
        (words[index], carry) = words[index].carrying_add(carry, Limb::new(0));
        index += 1;
    }
    debug_assert_eq!(carry, Limb::new(0));
}

#[cfg(feature = "alloc")]
fn power_of_two_shift(words: &[Limb]) -> Option<usize> {
    let mut found = None;
    for (index, word) in words.iter().enumerate() {
        if word.to_word() == 0 {
            continue;
        }
        if found.is_some() || !word.to_word().is_power_of_two() {
            return None;
        }
        found = Some(index * Word::BITS as usize + word.to_word().trailing_zeros() as usize);
    }
    found
}

#[cfg(feature = "alloc")]
pub(crate) fn div_rem(dividend: &[Limb], divisor: &[Limb]) -> (Vec<Limb>, Vec<Limb>) {
    assert!(significant_len(divisor) != 0, "attempted to divide by zero");
    let dividend_len = significant_len(dividend);
    let divisor_len = significant_len(divisor);
    if divisor_len == 1 {
        let mut quotient = dividend[..dividend_len].to_vec();
        let remainder = div_rem_small(&mut quotient, divisor[0].to_word());
        let remainder = if remainder == 0 {
            Vec::new()
        } else {
            vec![Limb::new(remainder)]
        };
        return (quotient, remainder);
    }
    if dividend_len < divisor_len || cmp(dividend, divisor) == Ordering::Less {
        let mut remainder = dividend[..dividend_len].to_vec();
        normalize(&mut remainder);
        return (Vec::new(), remainder);
    }

    // Knuth, TAOCP volume 2, Algorithm D. Normalizing the divisor makes the
    // two-word quotient estimate fit in `WideWord` on both 32- and 64-bit
    // targets.
    let normalization_shift = divisor[divisor_len - 1].to_word().leading_zeros() as usize;
    let normalized_divisor = shl(&divisor[..divisor_len], normalization_shift);
    debug_assert_eq!(normalized_divisor.len(), divisor_len);
    let mut normalized_dividend = shl(&dividend[..dividend_len], normalization_shift);
    normalized_dividend.resize(dividend_len + 1, Limb::new(0));

    let quotient_len = dividend_len - divisor_len + 1;
    let mut quotient = vec![Limb::new(0); quotient_len];
    let base = (1 as WideWord) << Word::BITS;
    let divisor_high = normalized_divisor[divisor_len - 1].to_word() as WideWord;

    for offset in (0..quotient_len).rev() {
        let numerator = ((normalized_dividend[offset + divisor_len].to_word() as WideWord)
            << Word::BITS)
            | normalized_dividend[offset + divisor_len - 1].to_word() as WideWord;
        let mut estimate = numerator / divisor_high;
        let mut remainder = numerator % divisor_high;

        if divisor_len > 1 {
            let divisor_next = normalized_divisor[divisor_len - 2].to_word() as WideWord;
            let dividend_next = normalized_dividend[offset + divisor_len - 2].to_word() as WideWord;
            while estimate == base
                || (remainder < base
                    && estimate * divisor_next > (remainder << Word::BITS) + dividend_next)
            {
                estimate -= 1;
                remainder += divisor_high;
                if remainder >= base {
                    break;
                }
            }
        }

        let estimate_word = estimate as Word;
        let mut borrow = 0 as WideWord;
        for index in 0..divisor_len {
            let product = estimate_word as WideWord
                * normalized_divisor[index].to_word() as WideWord
                + borrow;
            let (difference, underflow) = normalized_dividend[offset + index]
                .to_word()
                .overflowing_sub(product as Word);
            normalized_dividend[offset + index] = Limb::new(difference);
            borrow = (product >> Word::BITS) + underflow as WideWord;
        }

        let high_index = offset + divisor_len;
        let (difference, negative) = normalized_dividend[high_index]
            .to_word()
            .overflowing_sub(borrow as Word);
        normalized_dividend[high_index] = Limb::new(difference);
        if negative {
            estimate -= 1;
            let mut carry = Limb::new(0);
            for index in 0..divisor_len {
                (normalized_dividend[offset + index], carry) = normalized_dividend[offset + index]
                    .carrying_add(normalized_divisor[index], carry);
            }
            normalized_dividend[high_index] = Limb::new(
                normalized_dividend[high_index]
                    .to_word()
                    .wrapping_add(carry.to_word()),
            );
        }
        quotient[offset] = Limb::new(estimate as Word);
    }

    normalize(&mut quotient);
    let mut remainder = if normalization_shift == 0 {
        normalized_dividend[..divisor_len].to_vec()
    } else {
        shr(&normalized_dividend[..divisor_len], normalization_shift)
    };
    normalize(&mut remainder);
    (quotient, remainder)
}

#[cfg(feature = "alloc")]
pub(crate) fn shl(words: &[Limb], shift: usize) -> Vec<Limb> {
    if words.is_empty() {
        return Vec::new();
    }

    let word_shift = shift / Word::BITS as usize;
    let bit_shift = shift % Word::BITS as usize;
    let mut result = vec![Limb::new(0); words.len() + word_shift + usize::from(bit_shift != 0)];
    let mut carry = 0 as Word;

    for (index, word) in words.iter().enumerate() {
        let wide = ((word.to_word() as WideWord) << bit_shift) | carry as WideWord;
        result[index + word_shift] = Limb::new(wide as Word);
        carry = (wide >> Word::BITS) as Word;
    }
    if bit_shift != 0 {
        result[words.len() + word_shift] = Limb::new(carry);
    }

    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
pub(crate) fn shr(words: &[Limb], shift: usize) -> Vec<Limb> {
    let word_shift = shift / Word::BITS as usize;
    if word_shift >= words.len() {
        return Vec::new();
    }

    let bit_shift = shift % Word::BITS as usize;
    let mut result = vec![Limb::new(0); words.len() - word_shift];
    let mut carry = 0 as Word;

    for index in (word_shift..words.len()).rev() {
        let word = words[index].to_word();
        result[index - word_shift] = if bit_shift == 0 {
            Limb::new(word)
        } else {
            Limb::new((word >> bit_shift) | carry)
        };
        carry = if bit_shift == 0 {
            0
        } else {
            word << (Word::BITS as usize - bit_shift)
        };
    }

    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
pub(crate) fn bit_len(words: &[Limb]) -> usize {
    let len = significant_len(words);
    if len == 0 {
        0
    } else {
        (len - 1) * Word::BITS as usize
            + (Word::BITS - words[len - 1].to_word().leading_zeros()) as usize
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn truncated_bits_are_nonzero(words: &[Limb], shift: usize) -> bool {
    let word_shift = shift / Word::BITS as usize;
    let bit_shift = shift % Word::BITS as usize;

    if words
        .iter()
        .take(word_shift.min(words.len()))
        .any(|word| word.to_word() != 0)
    {
        return true;
    }
    bit_shift != 0
        && words
            .get(word_shift)
            .is_some_and(|word| word.to_word() & (((1 as Word) << bit_shift) - 1) != 0)
}

#[cfg(feature = "alloc")]
pub(crate) fn add_small(words: &mut Vec<Limb>, value: Word) {
    let mut carry = Limb::new(value);
    let mut index = 0;
    while carry.to_word() != 0 && index < words.len() {
        let (word, next) = words[index].carrying_add(carry, Limb::new(0));
        words[index] = word;
        carry = next;
        index += 1;
    }
    if carry.to_word() != 0 {
        words.push(carry);
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn mul_small(words: &mut Vec<Limb>, value: Word) {
    if value == 0 {
        words.clear();
        return;
    }

    let mut carry = 0 as Word;
    for word in words.iter_mut() {
        let wide = word.to_word() as WideWord * value as WideWord + carry as WideWord;
        *word = Limb::new(wide as Word);
        carry = (wide >> Word::BITS) as Word;
    }
    if carry != 0 {
        words.push(Limb::new(carry));
    }
}

#[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
pub(crate) fn div_rem_small(words: &mut Vec<Limb>, divisor: Word) -> Word {
    let mut remainder = 0 as WideWord;
    for word in words.iter_mut().rev() {
        let wide = (remainder << Word::BITS) | word.to_word() as WideWord;
        *word = Limb::new((wide / divisor as WideWord) as Word);
        remainder = wide % divisor as WideWord;
    }
    normalize(words);
    remainder as Word
}

#[cfg(test)]
#[path = "arithmetic_tests.rs"]
pub(crate) mod tests;
