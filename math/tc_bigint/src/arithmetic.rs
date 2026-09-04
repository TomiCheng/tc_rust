//! Internal arithmetic over little-endian unsigned limbs.

use core::cmp::Ordering;

use crate::{Limb, WideWord, Word};

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
    while words.last() == Some(&Limb(0)) {
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
        .rposition(|word| word.0 != 0)
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

    let mut result = vec![Limb(0); lhs.len() + rhs.len()];
    for (left_index, left) in lhs.iter().enumerate() {
        if left.0 == 0 {
            continue;
        }
        let mut carry = 0 as Word;
        for (right_index, right) in rhs.iter().enumerate() {
            let index = left_index + right_index;
            let wide = left.0 as WideWord * right.0 as WideWord
                + result[index].0 as WideWord
                + carry as WideWord;
            result[index] = Limb(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        result[left_index + rhs.len()] = Limb(carry);
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
    let mut result = vec![Limb(0); short.len() + long.len()];
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
    let mut carry = Limb(0);
    for index in 0..len {
        let left = lhs.get(index).copied().unwrap_or_default();
        let right = rhs.get(index).copied().unwrap_or_default();
        let (sum, next_carry) = left.carrying_add(right, carry);
        result.push(sum);
        carry = next_carry;
    }
    if carry.0 != 0 {
        result.push(carry);
    }
    result
}

#[cfg(feature = "alloc")]
fn sub_assign_magnitude(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    debug_assert!(cmp(lhs, rhs) != Ordering::Less);
    let mut borrow = Limb(0);
    for (index, left) in lhs.iter_mut().enumerate() {
        let right = rhs.get(index).copied().unwrap_or_default();
        (*left, borrow) = left.borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb(0));
    normalize(lhs);
}

#[cfg(feature = "alloc")]
fn add_shifted_assign(lhs: &mut Vec<Limb>, rhs: &[Limb], shift: usize) {
    if rhs.is_empty() {
        return;
    }
    let required_len = shift + rhs.len();
    if lhs.len() < required_len {
        lhs.resize(required_len, Limb(0));
    }

    let mut carry = Limb(0);
    for (index, right) in rhs.iter().copied().enumerate() {
        let output = shift + index;
        (lhs[output], carry) = lhs[output].carrying_add(right, carry);
    }
    let mut output = required_len;
    while carry.0 != 0 {
        if output == lhs.len() {
            lhs.push(carry);
            break;
        }
        (lhs[output], carry) = lhs[output].carrying_add(Limb(0), carry);
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

    let mut result = vec![Limb(0); 2 * len];
    for left in 0..len {
        let diagonal = words[left].0 as WideWord * words[left].0 as WideWord;
        add_wide_at(&mut result, left * 2, diagonal);
        for right in left + 1..len {
            let product = words[left].0 as WideWord * words[right].0 as WideWord;
            add_wide_at(&mut result, left + right, product);
            add_wide_at(&mut result, left + right, product);
        }
    }

    normalize(&mut result);
    result
}

#[cfg(feature = "alloc")]
fn add_wide_at(words: &mut [Limb], index: usize, value: WideWord) {
    let low = Limb(value as Word);
    let high = Limb((value >> Word::BITS) as Word);
    let (word, carry) = words[index].carrying_add(low, Limb(0));
    words[index] = word;
    let (word, mut carry) = words[index + 1].carrying_add(high, carry);
    words[index + 1] = word;

    let mut index = index + 2;
    while carry.0 != 0 && index < words.len() {
        (words[index], carry) = words[index].carrying_add(carry, Limb(0));
        index += 1;
    }
    debug_assert_eq!(carry, Limb(0));
}

#[cfg(feature = "alloc")]
fn power_of_two_shift(words: &[Limb]) -> Option<usize> {
    let mut found = None;
    for (index, word) in words.iter().enumerate() {
        if word.0 == 0 {
            continue;
        }
        if found.is_some() || !word.0.is_power_of_two() {
            return None;
        }
        found = Some(index * Word::BITS as usize + word.0.trailing_zeros() as usize);
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
        let remainder = div_rem_small(&mut quotient, divisor[0].0);
        let remainder = if remainder == 0 {
            Vec::new()
        } else {
            vec![Limb(remainder)]
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
    let normalization_shift = divisor[divisor_len - 1].0.leading_zeros() as usize;
    let normalized_divisor = shl(&divisor[..divisor_len], normalization_shift);
    debug_assert_eq!(normalized_divisor.len(), divisor_len);
    let mut normalized_dividend = shl(&dividend[..dividend_len], normalization_shift);
    normalized_dividend.resize(dividend_len + 1, Limb(0));

    let quotient_len = dividend_len - divisor_len + 1;
    let mut quotient = vec![Limb(0); quotient_len];
    let base = (1 as WideWord) << Word::BITS;
    let divisor_high = normalized_divisor[divisor_len - 1].0 as WideWord;

    for offset in (0..quotient_len).rev() {
        let numerator = ((normalized_dividend[offset + divisor_len].0 as WideWord) << Word::BITS)
            | normalized_dividend[offset + divisor_len - 1].0 as WideWord;
        let mut estimate = numerator / divisor_high;
        let mut remainder = numerator % divisor_high;

        if divisor_len > 1 {
            let divisor_next = normalized_divisor[divisor_len - 2].0 as WideWord;
            let dividend_next = normalized_dividend[offset + divisor_len - 2].0 as WideWord;
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
            let product =
                estimate_word as WideWord * normalized_divisor[index].0 as WideWord + borrow;
            let (difference, underflow) = normalized_dividend[offset + index]
                .0
                .overflowing_sub(product as Word);
            normalized_dividend[offset + index] = Limb(difference);
            borrow = (product >> Word::BITS) + underflow as WideWord;
        }

        let high_index = offset + divisor_len;
        let (difference, negative) = normalized_dividend[high_index]
            .0
            .overflowing_sub(borrow as Word);
        normalized_dividend[high_index] = Limb(difference);
        if negative {
            estimate -= 1;
            let mut carry = Limb(0);
            for index in 0..divisor_len {
                (normalized_dividend[offset + index], carry) = normalized_dividend[offset + index]
                    .carrying_add(normalized_divisor[index], carry);
            }
            normalized_dividend[high_index].0 =
                normalized_dividend[high_index].0.wrapping_add(carry.0);
        }
        quotient[offset] = Limb(estimate as Word);
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
    let mut result = vec![Limb(0); words.len() + word_shift + usize::from(bit_shift != 0)];
    let mut carry = 0 as Word;

    for (index, word) in words.iter().enumerate() {
        let wide = ((word.0 as WideWord) << bit_shift) | carry as WideWord;
        result[index + word_shift] = Limb(wide as Word);
        carry = (wide >> Word::BITS) as Word;
    }
    if bit_shift != 0 {
        result[words.len() + word_shift] = Limb(carry);
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
    let mut result = vec![Limb(0); words.len() - word_shift];
    let mut carry = 0 as Word;

    for index in (word_shift..words.len()).rev() {
        let word = words[index].0;
        result[index - word_shift] = if bit_shift == 0 {
            Limb(word)
        } else {
            Limb((word >> bit_shift) | carry)
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
        (len - 1) * Word::BITS as usize + (Word::BITS - words[len - 1].0.leading_zeros()) as usize
    }
}

#[cfg(feature = "alloc")]
pub(crate) fn truncated_bits_are_nonzero(words: &[Limb], shift: usize) -> bool {
    let word_shift = shift / Word::BITS as usize;
    let bit_shift = shift % Word::BITS as usize;

    if words
        .iter()
        .take(word_shift.min(words.len()))
        .any(|word| word.0 != 0)
    {
        return true;
    }
    bit_shift != 0
        && words
            .get(word_shift)
            .is_some_and(|word| word.0 & (((1 as Word) << bit_shift) - 1) != 0)
}

#[cfg(feature = "alloc")]
pub(crate) fn add_small(words: &mut Vec<Limb>, value: Word) {
    let mut carry = Limb(value);
    let mut index = 0;
    while carry.0 != 0 && index < words.len() {
        let (word, next) = words[index].carrying_add(carry, Limb(0));
        words[index] = word;
        carry = next;
        index += 1;
    }
    if carry.0 != 0 {
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
        let wide = word.0 as WideWord * value as WideWord + carry as WideWord;
        word.0 = wide as Word;
        carry = (wide >> Word::BITS) as Word;
    }
    if carry != 0 {
        words.push(Limb(carry));
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
        let wide = (remainder << Word::BITS) | word.0 as WideWord;
        word.0 = (wide / divisor as WideWord) as Word;
        remainder = wide % divisor as WideWord;
    }
    normalize(words);
    remainder as Word
}

pub(crate) fn fixed_cmp<const N: usize>(lhs: &[Limb; N], rhs: &[Limb; N]) -> Ordering {
    lhs.iter().rev().cmp(rhs.iter().rev())
}

pub(crate) fn fixed_add<const N: usize>(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
    let mut result = [Limb(0); N];
    let mut carry = Limb(0);
    for index in 0..N {
        (result[index], carry) = lhs[index].carrying_add(rhs[index], carry);
    }
    (result, carry.0 != 0)
}

pub(crate) fn fixed_sub<const N: usize>(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
    let mut result = [Limb(0); N];
    let mut borrow = Limb(0);
    for index in 0..N {
        (result[index], borrow) = lhs[index].borrowing_sub(rhs[index], borrow);
    }
    (result, borrow.0 != 0)
}

pub(crate) fn fixed_mul<const N: usize>(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
    let mut result = [Limb(0); N];
    let mut overflow = false;

    for (left_index, left) in lhs.iter().enumerate() {
        let mut carry = 0 as Word;
        for (right_index, right) in rhs.iter().enumerate() {
            let index = left_index + right_index;
            if index >= N {
                overflow |= left.0 != 0 && right.0 != 0;
                continue;
            }
            let wide = left.0 as WideWord * right.0 as WideWord
                + result[index].0 as WideWord
                + carry as WideWord;
            result[index] = Limb(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        overflow |= carry != 0;
    }

    (result, overflow)
}

#[inline]
pub(crate) fn fixed_mul_wide<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
) -> ([Limb; N], [Limb; N]) {
    let mut low = [Limb(0); N];
    let mut high = [Limb(0); N];

    for (left_index, left) in lhs.iter().enumerate() {
        let mut carry = 0 as Word;
        for (right_index, right) in rhs.iter().enumerate() {
            let index = left_index + right_index;
            let current = if index < N {
                low[index].0
            } else {
                high[index - N].0
            };
            let wide =
                left.0 as WideWord * right.0 as WideWord + current as WideWord + carry as WideWord;
            let output = Limb(wide as Word);
            if index < N {
                low[index] = output;
            } else {
                high[index - N] = output;
            }
            carry = (wide >> Word::BITS) as Word;
        }
        if N != 0 {
            high[left_index] = Limb(carry);
        }
    }

    (low, high)
}

pub(crate) fn fixed_div_rem<const N: usize>(
    dividend: &[Limb; N],
    divisor: &[Limb; N],
) -> ([Limb; N], [Limb; N]) {
    let dividend_len = fixed_significant_len(dividend);
    let divisor_len = fixed_significant_len(divisor);
    assert!(divisor_len != 0, "attempted to divide by zero");

    let mut quotient = [Limb(0); N];
    if dividend_len < divisor_len || fixed_cmp(dividend, divisor) == Ordering::Less {
        return (quotient, *dividend);
    }

    if divisor_len == 1 {
        let divisor = divisor[0].0 as WideWord;
        let mut remainder = 0 as WideWord;
        for index in (0..dividend_len).rev() {
            let wide = (remainder << Word::BITS) | dividend[index].0 as WideWord;
            quotient[index] = Limb((wide / divisor) as Word);
            remainder = wide % divisor;
        }
        let mut remainder_words = [Limb(0); N];
        remainder_words[0] = Limb(remainder as Word);
        return (quotient, remainder_words);
    }

    let normalization_shift = divisor[divisor_len - 1].0.leading_zeros() as usize;
    let mut normalized_divisor = [Limb(0); N];
    let divisor_carry = fixed_shl_words(
        divisor,
        divisor_len,
        normalization_shift,
        &mut normalized_divisor,
    );
    debug_assert_eq!(divisor_carry, 0);

    let mut normalized_dividend = [Limb(0); N];
    let mut dividend_extra = fixed_shl_words(
        dividend,
        dividend_len,
        normalization_shift,
        &mut normalized_dividend,
    );
    if dividend_len < N {
        normalized_dividend[dividend_len] = Limb(dividend_extra);
        dividend_extra = 0;
    }

    let quotient_len = dividend_len - divisor_len + 1;
    let base = (1 as WideWord) << Word::BITS;
    let divisor_high = normalized_divisor[divisor_len - 1].0 as WideWord;

    for offset in (0..quotient_len).rev() {
        let numerator = ((fixed_word(&normalized_dividend, dividend_extra, offset + divisor_len)
            as WideWord)
            << Word::BITS)
            | normalized_dividend[offset + divisor_len - 1].0 as WideWord;
        let mut estimate = numerator / divisor_high;
        let mut estimate_remainder = numerator % divisor_high;
        let divisor_next = normalized_divisor[divisor_len - 2].0 as WideWord;
        let dividend_next = normalized_dividend[offset + divisor_len - 2].0 as WideWord;
        while estimate == base
            || (estimate_remainder < base
                && estimate * divisor_next > (estimate_remainder << Word::BITS) + dividend_next)
        {
            estimate -= 1;
            estimate_remainder += divisor_high;
            if estimate_remainder >= base {
                break;
            }
        }

        let estimate_word = estimate as Word;
        let mut borrow = 0 as WideWord;
        for index in 0..divisor_len {
            let product =
                estimate_word as WideWord * normalized_divisor[index].0 as WideWord + borrow;
            let (difference, underflow) = normalized_dividend[offset + index]
                .0
                .overflowing_sub(product as Word);
            normalized_dividend[offset + index] = Limb(difference);
            borrow = (product >> Word::BITS) + underflow as WideWord;
        }

        let high_index = offset + divisor_len;
        let high = fixed_word(&normalized_dividend, dividend_extra, high_index);
        let (difference, negative) = high.overflowing_sub(borrow as Word);
        fixed_set_word(
            &mut normalized_dividend,
            &mut dividend_extra,
            high_index,
            difference,
        );
        if negative {
            estimate -= 1;
            let mut carry = Limb(0);
            for index in 0..divisor_len {
                (normalized_dividend[offset + index], carry) = normalized_dividend[offset + index]
                    .carrying_add(normalized_divisor[index], carry);
            }
            let high = fixed_word(&normalized_dividend, dividend_extra, high_index);
            fixed_set_word(
                &mut normalized_dividend,
                &mut dividend_extra,
                high_index,
                high.wrapping_add(carry.0),
            );
        }
        quotient[offset] = Limb(estimate as Word);
    }

    let mut remainder = [Limb(0); N];
    if normalization_shift == 0 {
        remainder[..divisor_len].copy_from_slice(&normalized_dividend[..divisor_len]);
    } else {
        for index in 0..divisor_len {
            let high = if index + 1 < divisor_len {
                normalized_dividend[index + 1].0
            } else {
                0
            };
            remainder[index] = Limb(
                (normalized_dividend[index].0 >> normalization_shift)
                    | (high << (Word::BITS as usize - normalization_shift)),
            );
        }
    }
    (quotient, remainder)
}

#[inline]
pub(crate) fn fixed_wide_rem<const N: usize>(
    low: &[Limb; N],
    high: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let modulus_len = fixed_significant_len(modulus);
    assert!(modulus_len != 0, "attempted to divide by zero");

    let high_len = fixed_significant_len(high);
    if high_len == 0 {
        return fixed_div_rem(low, modulus).1;
    }

    if modulus_len == 1 {
        let divisor = modulus[0].0 as WideWord;
        let mut remainder = 0 as WideWord;
        for word in high.iter().rev().chain(low.iter().rev()) {
            let wide = (remainder << Word::BITS) | word.0 as WideWord;
            remainder = wide % divisor;
        }
        let mut result = [Limb(0); N];
        result[0] = Limb(remainder as Word);
        return result;
    }

    let normalization_shift = modulus[modulus_len - 1].0.leading_zeros() as usize;
    let mut normalized_modulus = [Limb(0); N];
    let modulus_carry = fixed_shl_words(
        modulus,
        modulus_len,
        normalization_shift,
        &mut normalized_modulus,
    );
    debug_assert_eq!(modulus_carry, 0);

    // Process the normalized 2N-word dividend one word at a time. The current
    // remainder is the only dividend window Knuth's algorithm needs, so this
    // does not require an unstable `[Limb; 2 * N]` temporary.
    let input_len = N + high_len;
    let mut remainder = [Limb(0); N];
    let base = (1 as WideWord) << Word::BITS;
    let modulus_high = normalized_modulus[modulus_len - 1].0 as WideWord;
    let modulus_next = normalized_modulus[modulus_len - 2].0 as WideWord;

    // The first `modulus_len` most-significant words form a prefix smaller
    // than the normalized modulus. Seed the rolling remainder with that
    // prefix, then estimate only the quotient words that can be non-zero.
    let first_quotient_input = input_len + 1 - modulus_len;
    for (index, word) in remainder.iter_mut().take(modulus_len).enumerate() {
        *word = Limb(fixed_normalized_wide_word(
            low,
            high,
            first_quotient_input + index,
            normalization_shift,
        ));
    }
    debug_assert_eq!(fixed_cmp(&remainder, &normalized_modulus), Ordering::Less);

    for input_index in (0..first_quotient_input).rev() {
        let input_word = fixed_normalized_wide_word(low, high, input_index, normalization_shift);
        let mut window_high = remainder[modulus_len - 1].0;
        for index in (1..modulus_len).rev() {
            remainder[index] = remainder[index - 1];
        }
        remainder[0] = Limb(input_word);

        let numerator =
            ((window_high as WideWord) << Word::BITS) | remainder[modulus_len - 1].0 as WideWord;
        let mut estimate = numerator / modulus_high;
        let mut estimate_remainder = numerator % modulus_high;
        let dividend_next = remainder[modulus_len - 2].0 as WideWord;
        while estimate == base
            || (estimate_remainder < base
                && estimate * modulus_next > (estimate_remainder << Word::BITS) + dividend_next)
        {
            estimate -= 1;
            estimate_remainder += modulus_high;
            if estimate_remainder >= base {
                break;
            }
        }

        let estimate_word = estimate as Word;
        let mut borrow = 0 as WideWord;
        for index in 0..modulus_len {
            let product =
                estimate_word as WideWord * normalized_modulus[index].0 as WideWord + borrow;
            let (difference, underflow) = remainder[index].0.overflowing_sub(product as Word);
            remainder[index] = Limb(difference);
            borrow = (product >> Word::BITS) + underflow as WideWord;
        }

        let (difference, negative) = window_high.overflowing_sub(borrow as Word);
        window_high = difference;
        if negative {
            let mut carry = Limb(0);
            for index in 0..modulus_len {
                (remainder[index], carry) =
                    remainder[index].carrying_add(normalized_modulus[index], carry);
            }
            window_high = window_high.wrapping_add(carry.0);
        }
        debug_assert_eq!(window_high, 0);
    }

    if normalization_shift != 0 {
        for index in 0..modulus_len {
            let high = if index + 1 < modulus_len {
                remainder[index + 1].0
            } else {
                0
            };
            remainder[index] = Limb(
                (remainder[index].0 >> normalization_shift)
                    | (high << (Word::BITS as usize - normalization_shift)),
            );
        }
    }
    remainder
}

#[inline(always)]
fn fixed_normalized_wide_word<const N: usize>(
    low: &[Limb; N],
    high: &[Limb; N],
    index: usize,
    shift: usize,
) -> Word {
    let current = fixed_wide_word(low, high, index);
    if shift == 0 {
        return current;
    }
    let previous = index
        .checked_sub(1)
        .map_or(0, |previous| fixed_wide_word(low, high, previous));
    (current << shift) | (previous >> (Word::BITS as usize - shift))
}

#[inline(always)]
fn fixed_wide_word<const N: usize>(low: &[Limb; N], high: &[Limb; N], index: usize) -> Word {
    if index < N {
        low[index].0
    } else {
        high.get(index - N).map_or(0, |word| word.0)
    }
}

fn fixed_significant_len<const N: usize>(words: &[Limb; N]) -> usize {
    words
        .iter()
        .rposition(|word| word.0 != 0)
        .map_or(0, |index| index + 1)
}

fn fixed_shl_words<const N: usize>(
    input: &[Limb; N],
    len: usize,
    shift: usize,
    output: &mut [Limb; N],
) -> Word {
    debug_assert!(shift < Word::BITS as usize);
    if shift == 0 {
        output[..len].copy_from_slice(&input[..len]);
        return 0;
    }

    let mut carry = 0 as Word;
    for index in 0..len {
        let wide = ((input[index].0 as WideWord) << shift) | carry as WideWord;
        output[index] = Limb(wide as Word);
        carry = (wide >> Word::BITS) as Word;
    }
    carry
}

fn fixed_word<const N: usize>(words: &[Limb; N], extra: Word, index: usize) -> Word {
    if index < N {
        words[index].0
    } else {
        debug_assert_eq!(index, N);
        extra
    }
}

fn fixed_set_word<const N: usize>(
    words: &mut [Limb; N],
    extra: &mut Word,
    index: usize,
    value: Word,
) {
    if index < N {
        words[index] = Limb(value);
    } else {
        debug_assert_eq!(index, N);
        *extra = value;
    }
}

pub(crate) fn fixed_wrapping_neg<const N: usize>(words: &[Limb; N]) -> [Limb; N] {
    let inverted = words.map(|word| Limb(!word.0));
    let mut one = [Limb(0); N];
    if N != 0 {
        one[0] = Limb(1);
    }
    fixed_add(&inverted, &one).0
}

pub(crate) fn fixed_is_negative<const N: usize>(words: &[Limb; N]) -> bool {
    words
        .last()
        .is_some_and(|word| word.0 >> (Word::BITS - 1) != 0)
}

pub(crate) fn fixed_abs<const N: usize>(words: &[Limb; N]) -> [Limb; N] {
    if fixed_is_negative(words) {
        fixed_wrapping_neg(words)
    } else {
        *words
    }
}

pub(crate) fn fixed_gcd<const N: usize>(lhs: &[Limb; N], rhs: &[Limb; N]) -> [Limb; N] {
    let mut left = *lhs;
    let mut right = *rhs;
    while !fixed_is_zero(&right) {
        let remainder = fixed_div_rem(&left, &right).1;
        left = right;
        right = remainder;
    }
    left
}

pub(crate) fn fixed_bit_len<const N: usize>(words: &[Limb; N]) -> usize {
    words
        .iter()
        .rposition(|word| word.0 != 0)
        .map_or(0, |index| {
            index * Word::BITS as usize + (Word::BITS - words[index].0.leading_zeros()) as usize
        })
}

pub(crate) fn fixed_test_bit<const N: usize>(words: &[Limb; N], index: usize) -> bool {
    words[index / Word::BITS as usize].0 >> (index % Word::BITS as usize) & 1 != 0
}

pub(crate) fn fixed_is_zero<const N: usize>(words: &[Limb; N]) -> bool {
    words.iter().all(|word| word.0 == 0)
}

pub(crate) fn fixed_is_one<const N: usize>(words: &[Limb; N]) -> bool {
    words.first() == Some(&Limb(1)) && words.iter().skip(1).all(|word| word.0 == 0)
}

#[cfg(test)]
pub(crate) fn fixed_shr_one<const N: usize>(words: &mut [Limb; N]) {
    let mut carry = 0 as Word;
    for word in words.iter_mut().rev() {
        let next = word.0 << (Word::BITS - 1);
        word.0 = (word.0 >> 1) | carry;
        carry = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Words = [Limb; 2];

    #[test]
    fn fixed_add_sub_mul_and_compare_cover_carry_borrow_and_overflow() {
        let one = [Limb(1), Limb(0)];
        let max = [Limb(Word::MAX), Limb(Word::MAX)];

        assert_eq!(fixed_cmp(&one, &max), Ordering::Less);
        assert_eq!(fixed_add(&one, &one), ([Limb(2), Limb(0)], false));
        assert_eq!(fixed_add(&max, &one), ([Limb(0), Limb(0)], true));
        assert_eq!(fixed_sub(&one, &one), ([Limb(0), Limb(0)], false));
        assert_eq!(
            fixed_sub(&[Limb(0), Limb(1)], &one),
            ([Limb(Word::MAX), Limb(0)], false)
        );
        assert!(fixed_sub(&[Limb(0), Limb(0)], &one).1);

        assert_eq!(
            fixed_mul(&[Limb(3), Limb(0)], &[Limb(7), Limb(0)]),
            ([Limb(21), Limb(0)], false)
        );
        assert!(fixed_mul(&max, &max).1);
    }

    #[test]
    fn fixed_wide_multiplication_preserves_both_product_halves() {
        let lhs = [Limb(3), Limb(1)];
        let rhs = [Limb(5), Limb(1)];
        let (low, high) = fixed_mul_wide(&lhs, &rhs);
        assert_eq!(low, [Limb(15), Limb(8)]);
        assert_eq!(high, [Limb(1), Limb(0)]);
    }

    #[test]
    fn fixed_wide_remainder_handles_a_full_width_modulus() {
        type Wide = [Limb; 4];

        let modulus: Wide = [Limb(Word::MAX); 4];
        let mut value = modulus;
        value[0] = Limb(Word::MAX - 1);
        let (low, high) = fixed_mul_wide(&value, &value);
        assert_eq!(
            fixed_wide_rem(&low, &high, &modulus),
            [Limb(1), Limb(0), Limb(0), Limb(0)]
        );

        let radix_low = [Limb(0); 4];
        let radix_high = [Limb(1), Limb(0), Limb(0), Limb(0)];
        assert_eq!(
            fixed_wide_rem(&radix_low, &radix_high, &modulus),
            [Limb(1), Limb(0), Limb(0), Limb(0)]
        );
    }

    #[test]
    fn fixed_division_sign_and_gcd_helpers_cover_all_results() {
        let value: Words = [Limb(100), Limb(0)];
        let divisor: Words = [Limb(9), Limb(0)];
        assert_eq!(
            fixed_div_rem(&value, &divisor),
            ([Limb(11), Limb(0)], [Limb(1), Limb(0)])
        );

        let minus_one = [Limb(Word::MAX), Limb(Word::MAX)];
        assert!(fixed_is_negative(&minus_one));
        assert_eq!(fixed_wrapping_neg(&minus_one), [Limb(1), Limb(0)]);
        assert_eq!(fixed_abs(&minus_one), [Limb(1), Limb(0)]);
        assert_eq!(fixed_abs(&value), value);
        assert_eq!(
            fixed_gcd(&[Limb(48), Limb(0)], &[Limb(18), Limb(0)]),
            [Limb(6), Limb(0)]
        );
    }

    #[test]
    fn fixed_right_shift_helper_crosses_limb_boundaries() {
        let mut value = [Limb(0), Limb(1)];
        fixed_shr_one(&mut value);
        assert_eq!(value, [Limb(1 << (Word::BITS - 1)), Limb(0)]);
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn fixed_division_rejects_zero() {
        let _ = fixed_div_rem(&[Limb(1)], &[Limb(0)]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_normalization_and_comparison_are_directly_covered() {
        let mut words = vec![Limb(1), Limb(0), Limb(0)];
        normalize(&mut words);
        assert_eq!(words, [Limb(1)]);
        assert_eq!(significant_len(&[Limb(1), Limb(0)]), 1);
        assert_eq!(cmp(&[Limb(1), Limb(0)], &[Limb(2)]), Ordering::Less);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn optimized_square_matches_independent_multiplication_for_multi_limb_values() {
        let cases = [
            vec![],
            vec![Limb(1)],
            vec![Limb(Word::MAX)],
            vec![Limb(3), Limb(5)],
            vec![Limb(Word::MAX), Limb(Word::MAX)],
            vec![Limb(0), Limb(1), Limb(7)],
            vec![Limb(Word::MAX), Limb(0), Limb(Word::MAX), Limb(17)],
        ];

        for value in cases {
            let copy = value.clone();
            assert_eq!(square(&value), mul(&value, &copy), "value={value:?}");
            assert_eq!(mul(&value, &value), square(&value));
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn karatsuba_matches_schoolbook_around_the_threshold_and_for_uneven_lengths() {
        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        fn random_words(state: &mut u64, len: usize) -> Vec<Limb> {
            let mut words = (0..len).map(|_| Limb(next_word(state))).collect::<Vec<_>>();
            words[len - 1].0 |= 1;
            words
        }

        let lengths = [
            (KARATSUBA_THRESHOLD - 1, KARATSUBA_THRESHOLD - 1),
            (KARATSUBA_THRESHOLD, KARATSUBA_THRESHOLD),
            (KARATSUBA_THRESHOLD + 1, KARATSUBA_THRESHOLD),
            (KARATSUBA_THRESHOLD, KARATSUBA_THRESHOLD + 1),
            (KARATSUBA_THRESHOLD, KARATSUBA_THRESHOLD * 2 + 1),
            (KARATSUBA_THRESHOLD, KARATSUBA_THRESHOLD * 3 + 7),
            (KARATSUBA_THRESHOLD * 2 - 1, KARATSUBA_THRESHOLD * 2 + 1),
        ];
        let mut state = 0x082e_fa98_ec4e_6c89_u64;

        for (case, (lhs_len, rhs_len)) in lengths.into_iter().enumerate() {
            for repetition in 0..32 {
                let lhs = random_words(&mut state, lhs_len);
                let rhs = random_words(&mut state, rhs_len);
                let expected = schoolbook_mul(&lhs, &rhs);
                assert_eq!(
                    mul(&lhs, &rhs),
                    expected,
                    "case {case}, repetition {repetition}"
                );
                assert_eq!(
                    mul(&rhs, &lhs),
                    expected,
                    "reversed case {case}, repetition {repetition}"
                );

                let expected_square = schoolbook_square(&lhs);
                let distinct = lhs.clone();
                assert_eq!(
                    square(&lhs),
                    expected_square,
                    "square case {case}, repetition {repetition}"
                );
                assert_eq!(
                    square(&lhs),
                    mul(&lhs, &distinct),
                    "square/mul case {case}, repetition {repetition}"
                );
            }
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn karatsuba_middle_product_preserves_the_extra_sum_limb() {
        let lhs = vec![Limb(Word::MAX); KARATSUBA_THRESHOLD];
        let mut rhs = lhs.clone();
        rhs[KARATSUBA_THRESHOLD / 2] = Limb(Word::MAX - 1);

        assert_eq!(mul(&lhs, &rhs), schoolbook_mul(&lhs, &rhs));
        assert_eq!(square(&lhs), schoolbook_square(&lhs));
        assert_eq!(square(&lhs), mul(&lhs, &lhs.clone()));

        let mut sparse = vec![Limb(0); KARATSUBA_THRESHOLD];
        sparse[KARATSUBA_THRESHOLD / 2] = Limb(3);
        sparse[KARATSUBA_THRESHOLD - 1] = Limb(1);
        assert_eq!(mul(&sparse, &rhs), schoolbook_mul(&sparse, &rhs));
        assert_eq!(square(&sparse), schoolbook_square(&sparse));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn knuth_division_reconstructs_with_karatsuba_products() {
        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        let mut state = 0x4528_21e6_38d0_1377_u64;
        for case in 0..128 {
            let dividend_len = KARATSUBA_THRESHOLD * 2 + case % 7;
            let divisor_len = KARATSUBA_THRESHOLD + case % 5;
            let mut dividend = (0..dividend_len)
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();
            let mut divisor = (0..divisor_len)
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();
            dividend[dividend_len - 1].0 |= 1;
            divisor[divisor_len - 1].0 |= 1;

            let (quotient, remainder) = div_rem(&dividend, &divisor);
            assert_eq!(cmp(&remainder, &divisor), Ordering::Less, "case {case}");
            let reconstructed = crate::BigUint::from_limbs(mul(&quotient, &divisor))
                + crate::BigUint::from_limbs(remainder);
            assert_eq!(
                reconstructed,
                crate::BigUint::from_limbs(dividend),
                "case {case}"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn multiplication_fast_paths_and_general_path_match_expected_values() {
        assert_eq!(
            power_of_two_shift(&[Limb(0), Limb(8)]),
            Some(Word::BITS as usize + 3)
        );
        assert_eq!(power_of_two_shift(&[Limb(3)]), None);
        assert_eq!(power_of_two_shift(&[]), None);
        assert_eq!(mul(&[], &[Limb(2)]), []);
        assert_eq!(mul(&[Limb(8)], &[Limb(7)]), [Limb(56)]);
        assert_eq!(mul(&[Limb(3)], &[Limb(7)]), [Limb(21)]);
        assert_eq!(
            mul(&[Limb(0), Limb(1)], &[Limb(0), Limb(1)]),
            [Limb(0), Limb(0), Limb(1)]
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn division_covers_small_word_multi_word_less_equal_and_exact_cases() {
        assert_eq!(
            div_rem(&[Limb(100)], &[Limb(9)]),
            (vec![Limb(11)], vec![Limb(1)])
        );
        assert_eq!(
            div_rem(&[Limb(2)], &[Limb(3), Limb(1)]),
            (vec![], vec![Limb(2)])
        );
        assert_eq!(
            div_rem(&[Limb(4), Limb(2)], &[Limb(4), Limb(2)]),
            (vec![Limb(1)], vec![])
        );

        let dividend = [Limb(5), Limb(9), Limb(2)];
        let divisor = [Limb(7), Limb(1)];
        let (quotient, remainder) = div_rem(&dividend, &divisor);
        let reconstructed = crate::BigUint::from_limbs(mul(&quotient, &divisor))
            + crate::BigUint::from_limbs(remainder.clone());
        assert_eq!(reconstructed.as_limbs(), dividend);
        assert_eq!(cmp(&remainder, &divisor), Ordering::Less);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn shifts_and_truncation_checks_cover_word_and_bit_boundaries() {
        let value = [Limb(1), Limb(2)];
        assert_eq!(shl(&value, 0), value);
        assert_eq!(
            shl(&value, Word::BITS as usize),
            [Limb(0), Limb(1), Limb(2)]
        );
        assert_eq!(shr(&value, Word::BITS as usize), [Limb(2)]);
        assert_eq!(shr(&value, 2 * Word::BITS as usize), []);
        assert!(truncated_bits_are_nonzero(&[Limb(1), Limb(2)], 1));
        assert!(!truncated_bits_are_nonzero(&[Limb(2)], 1));
        assert_eq!(bit_len(&[Limb(0), Limb(8)]), Word::BITS as usize + 4);
        assert_eq!(bit_len(&[]), 0);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn small_arithmetic_and_parsing_helpers_are_covered() {
        let mut words = vec![Limb(Word::MAX)];
        add_small(&mut words, 1);
        assert_eq!(words, [Limb(0), Limb(1)]);
        mul_small(&mut words, 3);
        assert_eq!(words, [Limb(0), Limb(3)]);
        mul_small(&mut words, 0);
        assert!(words.is_empty());

        assert_eq!(parse_unsigned("+FF", 16), Ok((false, vec![Limb(255)])));
        assert_eq!(parse_unsigned("-10", 10), Ok((true, vec![Limb(10)])));
        assert_eq!(parse_unsigned("-0", 10), Ok((false, vec![])));
        assert_eq!(parse_unsigned("?", 10), Err(ParseBigIntError::InvalidDigit));

        let mut quotient = vec![Limb(100)];
        assert_eq!(div_rem_small(&mut quotient, 9), 1);
        assert_eq!(quotient, [Limb(11)]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn knuth_division_and_square_match_algebraic_identities_for_random_limbs() {
        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        let mut state = 0x243f_6a88_85a3_08d3_u64;
        for case in 0..4_000 {
            let dividend_len = next_word(&mut state) as usize % 32 + 1;
            let divisor_len = next_word(&mut state) as usize % dividend_len + 1;
            let mut dividend = (0..dividend_len)
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();
            let mut divisor = (0..divisor_len)
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();

            // Exercise normalization and quotient-estimate edge cases as well
            // as uniformly generated words.
            match case % 4 {
                0 => divisor[divisor_len - 1] = Limb(1),
                1 => divisor[divisor_len - 1] = Limb(Word::MAX),
                2 => dividend[dividend_len - 1] = Limb(Word::MAX),
                _ => {}
            }
            if divisor.iter().all(|word| word.0 == 0) {
                divisor[0] = Limb(1);
            }

            let (quotient, remainder) = div_rem(&dividend, &divisor);
            let reconstructed = crate::BigUint::from_limbs(mul(&quotient, &divisor))
                + crate::BigUint::from_limbs(remainder.clone());
            let dividend = crate::BigUint::from_limbs(core::mem::take(&mut dividend));
            assert_eq!(reconstructed, dividend, "division case {case}");
            assert_eq!(cmp(&remainder, &divisor), Ordering::Less, "case {case}");

            let square_input = crate::BigUint::from_limbs(divisor.clone());
            assert_eq!(
                crate::BigUint::from_limbs(square(&divisor)),
                &square_input * &square_input,
                "square case {case}"
            );
        }
    }

    #[test]
    fn fixed_knuth_division_matches_algebraic_identities_for_random_limbs() {
        type Wide = [Limb; 8];

        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        let mut state = 0xa409_3822_299f_31d0_u64;
        for case in 0..4_000 {
            let mut dividend: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            let mut divisor: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            let divisor_len = next_word(&mut state) as usize % divisor.len() + 1;
            divisor[divisor_len..].fill(Limb(0));
            match case % 3 {
                0 => divisor[divisor_len - 1] = Limb(1),
                1 => divisor[divisor_len - 1] = Limb(Word::MAX),
                _ => {}
            }
            if divisor.iter().all(|word| word.0 == 0) {
                divisor[0] = Limb(1);
            }
            if case % 5 == 0 {
                let dividend_len = next_word(&mut state) as usize % dividend.len() + 1;
                dividend[dividend_len..].fill(Limb(0));
            }

            let (quotient, remainder) = fixed_div_rem(&dividend, &divisor);
            let (product, product_overflow) = fixed_mul(&quotient, &divisor);
            let (reconstructed, addition_overflow) = fixed_add(&product, &remainder);
            assert!(!product_overflow, "product overflow in case {case}");
            assert!(!addition_overflow, "addition overflow in case {case}");
            assert_eq!(reconstructed, dividend, "case {case}");
            assert_eq!(
                fixed_cmp(&remainder, &divisor),
                Ordering::Less,
                "case {case}"
            );
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn fixed_wide_remainder_matches_division_identities_for_random_limbs() {
        type Wide = [Limb; 4];

        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        let mut state = 0x1319_8a2e_0370_7344_u64;
        for case in 0..4_000 {
            let low: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            let high: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            let mut modulus: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            let modulus_len = next_word(&mut state) as usize % modulus.len() + 1;
            modulus[modulus_len..].fill(Limb(0));
            match case % 4 {
                0 => modulus[modulus_len - 1] = Limb(1),
                1 => modulus[modulus_len - 1] = Limb(Word::MAX),
                2 => modulus = [Limb(Word::MAX); 4],
                _ => {}
            }
            if modulus.iter().all(|word| word.0 == 0) {
                modulus[0] = Limb(1);
            }

            let remainder = fixed_wide_rem(&low, &high, &modulus);
            assert_eq!(
                fixed_cmp(&remainder, &modulus),
                Ordering::Less,
                "case {case}"
            );

            let mut dividend_words = Vec::with_capacity(8);
            dividend_words.extend_from_slice(&low);
            dividend_words.extend_from_slice(&high);
            let dividend = crate::BigUint::from_limbs(dividend_words);
            let divisor = crate::BigUint::from_limbs(modulus.to_vec());
            let quotient = &dividend / &divisor;
            let remainder = crate::BigUint::from_limbs(remainder.to_vec());
            assert_eq!(
                &quotient * &divisor + &remainder,
                dividend,
                "q * d + r identity failed in case {case}: low={low:?}, high={high:?}, modulus={modulus:?}, remainder={remainder:?}"
            );
        }
    }
}
