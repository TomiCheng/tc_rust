//! Montgomery and division-based modular multiplication helpers.

#[cfg(feature = "alloc")]
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use crate::arithmetic::{cmp, mul, normalize};

use crate::{Choice, ConditionallySelectable, Limb, LimbArray, WideWord, Word};

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
    debug_assert!(len != 0 && modulus[0].to_word() & 1 == 1);
    debug_assert!(cmp(lhs, modulus) == Ordering::Less);
    debug_assert!(cmp(rhs, modulus) == Ordering::Less);

    let mut product = mul(lhs, rhs);
    product.resize(len * 2 + 1, Limb::new(0));
    for offset in 0..len {
        let multiplier = product[offset].to_word().wrapping_mul(inverse);
        let mut carry = 0 as Word;
        for index in 0..len {
            let wide = multiplier as WideWord * modulus[index].to_word() as WideWord
                + product[offset + index].to_word() as WideWord
                + carry as WideWord;
            product[offset + index] = Limb::new(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }

        let mut index = offset + len;
        let mut wide = product[index].to_word() as WideWord + carry as WideWord;
        product[index] = Limb::new(wide as Word);
        carry = (wide >> Word::BITS) as Word;
        while carry != 0 {
            index += 1;
            wide = product[index].to_word() as WideWord + carry as WideWord;
            product[index] = Limb::new(wide as Word);
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
    let mut borrow = Limb::new(0);
    for index in 0..lhs.len() {
        let right = rhs.get(index).copied().unwrap_or_default();
        (lhs[index], borrow) = lhs[index].borrowing_sub(right, borrow);
    }
    debug_assert_eq!(borrow, Limb::new(0));
    normalize(lhs);
}

#[inline]
pub(super) fn fixed_montgomery_mul<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
    inverse: Word,
) -> [Limb; N] {
    debug_assert!(!crate::LimbArray::new(*(modulus)).is_zero() && modulus[0].to_word() & 1 == 1);

    let mut result = [Limb::new(0); N];
    let mut high = 0 as Word;
    for right in rhs {
        let mut carry = 0 as Word;
        for index in 0..N {
            let wide = result[index].to_word() as WideWord
                + lhs[index].to_word() as WideWord * right.to_word() as WideWord
                + carry as WideWord;
            result[index] = Limb::new(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        let wide = high as WideWord + carry as WideWord;
        high = wide as Word;
        let upper = (wide >> Word::BITS) as Word;

        let multiplier = result[0].to_word().wrapping_mul(inverse);
        carry = 0;
        for index in 0..N {
            let wide = result[index].to_word() as WideWord
                + multiplier as WideWord * modulus[index].to_word() as WideWord
                + carry as WideWord;
            if index != 0 {
                result[index - 1] = Limb::new(wide as Word);
            } else {
                debug_assert_eq!(wide as Word, 0);
            }
            carry = (wide >> Word::BITS) as Word;
        }
        let wide = high as WideWord + carry as WideWord;
        result[N - 1] = Limb::new(wide as Word);
        high = upper + (wide >> Word::BITS) as Word;
        debug_assert!(high <= 1);
    }

    let (reduced, borrow) = {
        let (value, overflow) =
            crate::LimbArray::new(result).sub(&crate::LimbArray::new(*(modulus)));
        (value.into_limbs(), overflow)
    };
    LimbArray::conditional_select(
        &LimbArray::new(result),
        &LimbArray::new(reduced),
        Choice::from_lsb((high as u8) | ((!borrow) as u8)),
    )
    .into_limbs()
}

pub(super) fn fixed_mul_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let (low, high) = {
        let (low, high) = crate::LimbArray::new(*(lhs)).mul_wide(&crate::LimbArray::new(*(rhs)));
        (low.into_limbs(), high.into_limbs())
    };
    crate::LimbArray::new(low)
        .wide_rem(
            &crate::LimbArray::new(high),
            &crate::LimbArray::new(*(modulus)),
        )
        .into_limbs()
}

pub(super) fn fixed_add_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let (sum, carry) = {
        let (value, overflow) = crate::LimbArray::new(*(lhs)).add(&crate::LimbArray::new(*(rhs)));
        (value.into_limbs(), overflow)
    };
    let (reduced, borrow) = {
        let (value, overflow) = crate::LimbArray::new(sum).sub(&crate::LimbArray::new(*(modulus)));
        (value.into_limbs(), overflow)
    };
    LimbArray::conditional_select(
        &LimbArray::new(sum),
        &LimbArray::new(reduced),
        Choice::from_lsb((carry | !borrow) as u8),
    )
    .into_limbs()
}

pub(super) fn fixed_sub_mod<const N: usize>(
    lhs: &[Limb; N],
    rhs: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let (difference, borrow) = {
        let (value, overflow) = crate::LimbArray::new(*(lhs)).sub(&crate::LimbArray::new(*(rhs)));
        (value.into_limbs(), overflow)
    };
    let corrected = {
        let (value, overflow) =
            crate::LimbArray::new(difference).add(&crate::LimbArray::new(*(modulus)));
        (value.into_limbs(), overflow)
    }
    .0;
    LimbArray::conditional_select(
        &LimbArray::new(difference),
        &LimbArray::new(corrected),
        Choice::from_lsb(borrow as u8),
    )
    .into_limbs()
}

pub(super) fn fixed_one_mod<const N: usize>(modulus: &[Limb; N]) -> [Limb; N] {
    let mut one = [Limb::new(0); N];
    if N != 0 {
        one[0] = Limb::new(1);
    }
    {
        let (low, high) = crate::LimbArray::new(one).div_rem(&crate::LimbArray::new(*(modulus)));
        (low.into_limbs(), high.into_limbs())
    }
    .1
}
