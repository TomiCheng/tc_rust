//! Montgomery and division-based modular multiplication helpers.

#[cfg(feature = "alloc")]
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use crate::arithmetic::{cmp, mul, normalize};
use crate::arithmetic::{
    fixed_add, fixed_div_rem, fixed_is_zero, fixed_mul_wide, fixed_sub, fixed_wide_rem,
};
use crate::{Choice, ConditionallySelectable, Limb, WideWord, Word};

pub(super) fn montgomery_inverse(word: Word) -> Word {
    debug_assert_eq!(word & 1, 1);
    let mut inverse = 1 as Word;
    let mut correct_bits = 1;
    while correct_bits < Word::BITS {
        inverse = inverse.wrapping_mul((2 as Word).wrapping_sub(word.wrapping_mul(inverse)));
        correct_bits *= 2;
    }
    inverse.wrapping_neg()
}

#[cfg(feature = "alloc")]
pub(super) fn montgomery_mul(
    lhs: &[Limb],
    rhs: &[Limb],
    modulus: &[Limb],
    inverse: Word,
) -> Vec<Limb> {
    let len = modulus.len();
    debug_assert!(len != 0 && modulus[0].0 & 1 == 1);
    debug_assert!(cmp(lhs, modulus) == Ordering::Less);
    debug_assert!(cmp(rhs, modulus) == Ordering::Less);

    let mut product = mul(lhs, rhs);
    product.resize(len * 2 + 1, Limb(0));
    for offset in 0..len {
        let multiplier = product[offset].0.wrapping_mul(inverse);
        let mut carry = 0 as Word;
        for index in 0..len {
            let wide = multiplier as WideWord * modulus[index].0 as WideWord
                + product[offset + index].0 as WideWord
                + carry as WideWord;
            product[offset + index] = Limb(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }

        let mut index = offset + len;
        let mut wide = product[index].0 as WideWord + carry as WideWord;
        product[index] = Limb(wide as Word);
        carry = (wide >> Word::BITS) as Word;
        while carry != 0 {
            index += 1;
            wide = product[index].0 as WideWord + carry as WideWord;
            product[index] = Limb(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
    }

    let mut result = product[len..].to_vec();
    normalize(&mut result);
    if cmp(&result, modulus) != Ordering::Less {
        subtract_assign(&mut result, modulus);
    }
    result
}

#[cfg(feature = "alloc")]
fn subtract_assign(lhs: &mut Vec<Limb>, rhs: &[Limb]) {
    debug_assert!(cmp(lhs, rhs) != Ordering::Less);
    let mut borrow = Limb(0);
    for index in 0..lhs.len() {
        let right = rhs.get(index).copied().unwrap_or_default();
        (lhs[index], borrow) = lhs[index].borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb(0));
    normalize(lhs);
}

#[inline]
pub(super) fn fixed_montgomery_mul<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
    inverse: Word,
) -> [Limb; N] {
    debug_assert!(!fixed_is_zero(modulus) && modulus[0].0 & 1 == 1);

    let mut result = [Limb(0); N];
    let mut high = 0 as Word;
    for right in rhs {
        let mut carry = 0 as Word;
        for index in 0..N {
            let wide = result[index].0 as WideWord
                + lhs[index].0 as WideWord * right.0 as WideWord
                + carry as WideWord;
            result[index] = Limb(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        let wide = high as WideWord + carry as WideWord;
        high = wide as Word;
        let upper = (wide >> Word::BITS) as Word;

        let multiplier = result[0].0.wrapping_mul(inverse);
        carry = 0;
        for index in 0..N {
            let wide = result[index].0 as WideWord
                + multiplier as WideWord * modulus[index].0 as WideWord
                + carry as WideWord;
            if index != 0 {
                result[index - 1] = Limb(wide as Word);
            } else {
                debug_assert_eq!(wide as Word, 0);
            }
            carry = (wide >> Word::BITS) as Word;
        }
        let wide = high as WideWord + carry as WideWord;
        result[N - 1] = Limb(wide as Word);
        high = upper + (wide >> Word::BITS) as Word;
        debug_assert!(high <= 1);
    }

    let (reduced, borrow) = fixed_sub(&result, modulus);
    <[Limb; N]>::conditional_select(
        &result,
        &reduced,
        Choice::from_lsb((high as u8) | ((!borrow) as u8)),
    )
}

pub(super) fn fixed_mul_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let (low, high) = fixed_mul_wide(lhs, rhs);
    fixed_wide_rem(&low, &high, modulus)
}

pub(super) fn fixed_add_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let (sum, carry) = fixed_add(lhs, rhs);
    let (reduced, borrow) = fixed_sub(&sum, modulus);
    <[Limb; N]>::conditional_select(&sum, &reduced, Choice::from_lsb((carry | !borrow) as u8))
}

pub(super) fn fixed_sub_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let (difference, borrow) = fixed_sub(lhs, rhs);
    let corrected = fixed_add(&difference, modulus).0;
    <[Limb; N]>::conditional_select(&difference, &corrected, Choice::from_lsb(borrow as u8))
}

pub(super) fn fixed_one_mod<const N: usize>(modulus: &[Limb; N]) -> [Limb; N] {
    let mut one = [Limb(0); N];
    if N != 0 {
        one[0] = Limb(1);
    }
    fixed_div_rem(&one, modulus).1
}
