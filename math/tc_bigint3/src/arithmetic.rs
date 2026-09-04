//! Internal arithmetic over little-endian unsigned limbs.

use core::cmp::Ordering;

use crate::{Limb, WideWord, Word};

#[cfg(feature = "alloc")]
use crate::ParseBigIntError;

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

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
fn sub_assign(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    debug_assert!(cmp(lhs, rhs) != Ordering::Less);
    let mut borrow = Limb(0);
    for index in 0..lhs.len() {
        let right = rhs.get(index).copied().unwrap_or_default();
        (lhs[index], borrow) = lhs[index].borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb(0));
    normalize(lhs);
}

#[cfg(feature = "alloc")]
pub(crate) fn mul(lhs: &[Limb], rhs: &[Limb]) -> Vec<Limb> {
    if lhs.is_empty() || rhs.is_empty() {
        return Vec::new();
    }

    if let Some(shift) = power_of_two_shift(lhs) {
        return shl(rhs, shift);
    }
    if let Some(shift) = power_of_two_shift(rhs) {
        return shl(lhs, shift);
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

/// Squares a magnitude while evaluating each off-diagonal product only once.
#[cfg(feature = "alloc")]
pub(crate) fn square(words: &[Limb]) -> Vec<Limb> {
    let len = significant_len(words);
    if len == 0 {
        return Vec::new();
    }

    // This is the symmetric schoolbook square used by the original crate,
    // indexed through the little-endian input without first reversing it.
    let mut result = vec![Limb(0); 2 * len];
    let mut output = (2 * len - 1) as isize;

    for big_endian_index in (1..len).rev() {
        let value = words[len - 1 - big_endian_index].0 as WideWord;
        let mut carry = value * value + result[output as usize].0 as WideWord;
        result[output as usize] = Limb(carry as Word);
        carry >>= Word::BITS;

        for other_big_endian_index in (0..big_endian_index).rev() {
            let product = value * words[len - 1 - other_big_endian_index].0 as WideWord;
            output -= 1;
            carry += result[output as usize].0 as WideWord + (((product as Word) << 1) as WideWord);
            result[output as usize] = Limb(carry as Word);
            carry = (carry >> Word::BITS) + (product >> (Word::BITS - 1));
        }

        output -= 1;
        carry += result[output as usize].0 as WideWord;
        result[output as usize] = Limb(carry as Word);

        output -= 1;
        if output >= 0 {
            result[output as usize] = Limb((carry >> Word::BITS) as Word);
        } else {
            debug_assert_eq!(carry >> Word::BITS, 0);
        }
        output += big_endian_index as isize;
    }

    let value = words[len - 1].0 as WideWord;
    let carry = value * value + result[output as usize].0 as WideWord;
    result[output as usize] = Limb(carry as Word);
    output -= 1;
    if output >= 0 {
        let index = output as usize;
        result[index].0 = result[index].0.wrapping_add((carry >> Word::BITS) as Word);
    } else {
        debug_assert_eq!(carry >> Word::BITS, 0);
    }

    result.reverse();
    normalize(&mut result);
    result
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
    let divisor_len = significant_len(divisor);
    if divisor_len == 1 {
        let mut quotient = dividend.to_vec();
        let remainder = div_rem_small(&mut quotient, divisor[0].0);
        let remainder = if remainder == 0 {
            Vec::new()
        } else {
            vec![Limb(remainder)]
        };
        return (quotient, remainder);
    }
    if cmp(dividend, divisor) == Ordering::Less {
        let mut remainder = dividend.to_vec();
        normalize(&mut remainder);
        return (Vec::new(), remainder);
    }

    let shift = bit_len(dividend) - bit_len(divisor);
    let mut shifted_divisor = shl(divisor, shift);
    let mut remainder = dividend.to_vec();
    normalize(&mut remainder);
    let mut quotient = vec![Limb(0); shift / Word::BITS as usize + 1];

    for bit in (0..=shift).rev() {
        if cmp(&remainder, &shifted_divisor) != Ordering::Less {
            sub_assign(&mut remainder, &shifted_divisor);
            quotient[bit / Word::BITS as usize].0 |= (1 as Word) << (bit % Word::BITS as usize);
        }
        shr_one_in_place(&mut shifted_divisor);
    }

    normalize(&mut quotient);
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

#[cfg(feature = "alloc")]
fn shr_one_in_place(words: &mut Vec<Limb>) {
    let mut carry = 0 as Word;
    for word in words.iter_mut().rev() {
        let next = word.0 << (Word::BITS - 1);
        word.0 = (word.0 >> 1) | carry;
        carry = next;
    }
    normalize(words);
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

pub(crate) fn fixed_div_rem<const N: usize>(
    dividend: &[Limb; N],
    divisor: &[Limb; N],
) -> ([Limb; N], [Limb; N]) {
    assert!(
        divisor.iter().any(|word| word.0 != 0),
        "attempted to divide by zero"
    );
    let mut quotient = [Limb(0); N];
    let mut remainder = [Limb(0); N];

    for bit in (0..N * Word::BITS as usize).rev() {
        let overflow = shift_left_one(&mut remainder);
        remainder[0].0 |=
            (dividend[bit / Word::BITS as usize].0 >> (bit % Word::BITS as usize)) & 1;

        if overflow || fixed_cmp(&remainder, divisor) != Ordering::Less {
            let (difference, _) = fixed_sub(&remainder, divisor);
            remainder = difference;
            quotient[bit / Word::BITS as usize].0 |= (1 as Word) << (bit % Word::BITS as usize);
        }
    }

    (quotient, remainder)
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

pub(crate) fn fixed_mod_inverse<const N: usize>(
    value: &[Limb; N],
    modulus: &[Limb; N],
) -> Option<[Limb; N]> {
    assert!(!fixed_is_zero(modulus), "modulus must be non-zero");
    let mut old_remainder = *modulus;
    let mut remainder = fixed_div_rem(value, modulus).1;
    let mut old_coefficient = [Limb(0); N];
    let mut coefficient = fixed_one_mod(modulus);

    while !fixed_is_zero(&remainder) {
        let (quotient, next_remainder) = fixed_div_rem(&old_remainder, &remainder);
        let product = fixed_mul_mod(&quotient, &coefficient, modulus);
        let next_coefficient = fixed_sub_mod(&old_coefficient, &product, modulus);
        old_remainder = remainder;
        remainder = next_remainder;
        old_coefficient = coefficient;
        coefficient = next_coefficient;
    }

    fixed_is_one(&old_remainder).then_some(old_coefficient)
}

pub(crate) fn fixed_mod_pow<const N: usize>(
    value: &[Limb; N],
    exponent: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    assert!(!fixed_is_zero(modulus), "modulus must be non-zero");
    let mut result = fixed_one_mod(modulus);
    let exponent_bits = fixed_bit_len(exponent);
    if exponent_bits == 0 {
        return result;
    }

    let base = fixed_div_rem(value, modulus).1;
    let window = exponentiation_window(exponent_bits);
    let table_len = 1 << (window - 1);
    let mut odd_powers = [[Limb(0); N]; 16];
    odd_powers[0] = base;
    if table_len > 1 {
        let base_squared = fixed_mul_mod(&base, &base, modulus);
        for index in 1..table_len {
            odd_powers[index] = fixed_mul_mod(&odd_powers[index - 1], &base_squared, modulus);
        }
    }

    let mut remaining_bits = exponent_bits;
    while remaining_bits != 0 {
        let high = remaining_bits - 1;
        if !fixed_test_bit(exponent, high) {
            result = fixed_mul_mod(&result, &result, modulus);
            remaining_bits -= 1;
            continue;
        }

        let mut low = remaining_bits.saturating_sub(window);
        while !fixed_test_bit(exponent, low) {
            low += 1;
        }
        let mut window_value = 0_usize;
        for bit in (low..=high).rev() {
            window_value = (window_value << 1) | usize::from(fixed_test_bit(exponent, bit));
        }
        for _ in low..=high {
            result = fixed_mul_mod(&result, &result, modulus);
        }
        result = fixed_mul_mod(&result, &odd_powers[window_value >> 1], modulus);
        remaining_bits = low;
    }
    result
}

pub(crate) fn exponentiation_window(exponent_bits: usize) -> usize {
    match exponent_bits {
        0..=7 => 1,
        8..=36 => 2,
        37..=140 => 3,
        141..=450 => 4,
        _ => 5,
    }
}

fn fixed_bit_len<const N: usize>(words: &[Limb; N]) -> usize {
    words
        .iter()
        .rposition(|word| word.0 != 0)
        .map_or(0, |index| {
            index * Word::BITS as usize + (Word::BITS - words[index].0.leading_zeros()) as usize
        })
}

fn fixed_test_bit<const N: usize>(words: &[Limb; N], index: usize) -> bool {
    words[index / Word::BITS as usize].0 >> (index % Word::BITS as usize) & 1 != 0
}

fn fixed_mul_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let mut result = [Limb(0); N];
    let mut addend = fixed_div_rem(lhs, modulus).1;
    let mut multiplier = *rhs;

    while !fixed_is_zero(&multiplier) {
        if multiplier[0].0 & 1 != 0 {
            result = fixed_add_mod(&result, &addend, modulus);
        }
        fixed_shr_one(&mut multiplier);
        if !fixed_is_zero(&multiplier) {
            addend = fixed_add_mod(&addend, &addend, modulus);
        }
    }
    result
}

fn fixed_add_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    debug_assert!(fixed_cmp(lhs, modulus) == Ordering::Less);
    debug_assert!(fixed_cmp(rhs, modulus) == Ordering::Less);
    let (distance, borrow) = fixed_sub(modulus, rhs);
    debug_assert!(!borrow);
    if fixed_cmp(lhs, &distance) != Ordering::Less {
        fixed_sub(lhs, &distance).0
    } else {
        let (sum, overflow) = fixed_add(lhs, rhs);
        debug_assert!(!overflow);
        sum
    }
}

fn fixed_sub_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    if fixed_cmp(lhs, rhs) != Ordering::Less {
        fixed_sub(lhs, rhs).0
    } else {
        let difference = fixed_sub(rhs, lhs).0;
        fixed_sub(modulus, &difference).0
    }
}

fn fixed_one_mod<const N: usize>(modulus: &[Limb; N]) -> [Limb; N] {
    let mut one = [Limb(0); N];
    if N != 0 {
        one[0] = Limb(1);
    }
    fixed_div_rem(&one, modulus).1
}

fn fixed_is_zero<const N: usize>(words: &[Limb; N]) -> bool {
    words.iter().all(|word| word.0 == 0)
}

fn fixed_is_one<const N: usize>(words: &[Limb; N]) -> bool {
    words.first() == Some(&Limb(1)) && words.iter().skip(1).all(|word| word.0 == 0)
}

fn fixed_shr_one<const N: usize>(words: &mut [Limb; N]) {
    let mut carry = 0 as Word;
    for word in words.iter_mut().rev() {
        let next = word.0 << (Word::BITS - 1);
        word.0 = (word.0 >> 1) | carry;
        carry = next;
    }
}

fn shift_left_one<const N: usize>(words: &mut [Limb; N]) -> bool {
    let mut carry = 0 as Word;
    for word in words {
        let next = word.0 >> (Word::BITS - 1);
        word.0 = (word.0 << 1) | carry;
        carry = next;
    }
    carry != 0
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
    fn fixed_modular_helpers_cover_reduction_and_non_invertible_values() {
        let three: Words = [Limb(3), Limb(0)];
        let four: Words = [Limb(4), Limb(0)];
        let seven: Words = [Limb(7), Limb(0)];

        assert_eq!(fixed_mod_inverse(&three, &seven), Some([Limb(5), Limb(0)]));
        assert_eq!(fixed_mod_inverse(&four, &[Limb(6), Limb(0)]), None);
        assert_eq!(fixed_mod_pow(&three, &four, &seven), [Limb(4), Limb(0)]);
        assert_eq!(fixed_mul_mod(&three, &four, &seven), [Limb(5), Limb(0)]);
        assert_eq!(fixed_add_mod(&three, &four, &seven), [Limb(0), Limb(0)]);
        assert_eq!(fixed_add_mod(&[Limb(1), Limb(0)], &three, &seven), four);
        assert_eq!(fixed_sub_mod(&four, &three, &seven), [Limb(1), Limb(0)]);
        assert_eq!(fixed_sub_mod(&three, &four, &seven), [Limb(6), Limb(0)]);
        assert_eq!(fixed_one_mod(&seven), [Limb(1), Limb(0)]);
        assert_eq!(fixed_one_mod(&[Limb(1), Limb(0)]), [Limb(0), Limb(0)]);
        assert!(fixed_is_zero(&[Limb(0), Limb(0)]));
        assert!(fixed_is_one(&[Limb(1), Limb(0)]));
        assert!(!fixed_is_one(&[Limb(1), Limb(1)]));
    }

    #[test]
    fn sliding_window_modular_power_matches_binary_reference_at_every_threshold() {
        type Wide = [Limb; 512 / Word::BITS as usize];

        fn reference(base: &Wide, exponent: &Wide, modulus: &Wide) -> Wide {
            let mut result = fixed_one_mod(modulus);
            let mut base = fixed_div_rem(base, modulus).1;
            let mut exponent = *exponent;
            while !fixed_is_zero(&exponent) {
                if exponent[0].0 & 1 != 0 {
                    result = fixed_mul_mod(&result, &base, modulus);
                }
                fixed_shr_one(&mut exponent);
                if !fixed_is_zero(&exponent) {
                    base = fixed_mul_mod(&base, &base, modulus);
                }
            }
            result
        }

        assert_eq!(exponentiation_window(7), 1);
        assert_eq!(exponentiation_window(8), 2);
        assert_eq!(exponentiation_window(37), 3);
        assert_eq!(exponentiation_window(141), 4);
        assert_eq!(exponentiation_window(451), 5);

        let base: Wide = core::array::from_fn(|index| if index == 0 { Limb(7) } else { Limb(0) });
        let modulus: Wide =
            core::array::from_fn(|index| if index == 0 { Limb(101) } else { Limb(0) });
        for bits in [1_usize, 8, 37, 141, 451] {
            let mut exponent: Wide = [Limb(0); 512 / Word::BITS as usize];
            exponent[(bits - 1) / Word::BITS as usize].0 |=
                (1 as Word) << ((bits - 1) % Word::BITS as usize);
            exponent[0].0 |= 0b1011;
            assert_eq!(fixed_bit_len(&exponent), bits.max(4));
            assert!(fixed_test_bit(&exponent, bits - 1));
            assert_eq!(
                fixed_mod_pow(&base, &exponent, &modulus),
                reference(&base, &exponent, &modulus)
            );
        }
    }

    #[test]
    fn fixed_shift_helpers_report_discarded_top_bits() {
        let mut value = [Limb(0), Limb(1)];
        fixed_shr_one(&mut value);
        assert_eq!(value, [Limb(1 << (Word::BITS - 1)), Limb(0)]);

        let mut max = [Limb(Word::MAX), Limb(Word::MAX)];
        assert!(shift_left_one(&mut max));
        assert_eq!(max, [Limb(Word::MAX - 1), Limb(Word::MAX)]);
    }

    #[test]
    #[should_panic(expected = "attempted to divide by zero")]
    fn fixed_division_rejects_zero() {
        let _ = fixed_div_rem(&[Limb(1)], &[Limb(0)]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn dynamic_normalization_comparison_addition_and_subtraction_are_directly_covered() {
        let mut words = vec![Limb(1), Limb(0), Limb(0)];
        normalize(&mut words);
        assert_eq!(words, [Limb(1)]);
        assert_eq!(significant_len(&[Limb(1), Limb(0)]), 1);
        assert_eq!(cmp(&[Limb(1), Limb(0)], &[Limb(2)]), Ordering::Less);
        let mut difference = vec![Limb(0), Limb(1)];
        sub_assign(&mut difference, &[Limb(1)]);
        assert_eq!(difference, [Limb(Word::MAX)]);

        let mut difference = vec![Limb(0), Limb(1)];
        sub_assign(&mut difference, &[Limb(1)]);
        assert_eq!(difference, [Limb(Word::MAX)]);
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
            assert_eq!(mul(&value, &value), square(&value), "same-slice fast path");
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
    fn small_arithmetic_parsing_and_in_place_shift_helpers_are_covered() {
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

        let mut shifted = vec![Limb(0), Limb(1)];
        shr_one_in_place(&mut shifted);
        assert_eq!(shifted, [Limb(1 << (Word::BITS - 1))]);
    }
}
