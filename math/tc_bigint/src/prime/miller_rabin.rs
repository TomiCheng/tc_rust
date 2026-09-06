//! Trial division and Miller-Rabin probable-prime testing.

use super::*;

use crate::modular::{FixedMontyForm, FixedMontyParams};
use crate::{Odd, WideWord};

#[cfg(feature = "alloc")]
use crate::modular::{MontyForm, MontyParams};

// Trial division removes inexpensive odd factors before Miller-Rabin. Two is
// handled separately by the even-value check in `*_is_probable_prime`.
const SMALL_PRIMES: &[Word] = &[
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

pub(super) fn remainder_word(words: &[Limb], divisor: Word) -> Word {
    let mut remainder = 0 as WideWord;
    for word in words.iter().rev() {
        let wide = (remainder << Word::BITS) | word.to_word() as WideWord;
        remainder = wide % divisor as WideWord;
    }
    remainder as Word
}

pub(super) fn equals_word(words: &[Limb], value: Word) -> bool {
    words.first().map_or(value == 0, |word| word.to_word() == value)
        && words.iter().skip(1).all(|word| word.to_word() == 0)
}

pub(super) fn has_small_factor(words: &[Limb]) -> Option<bool> {
    for &prime in SMALL_PRIMES {
        if remainder_word(words, prime) == 0 {
            return Some(!equals_word(words, prime));
        }
    }
    None
}

pub(super) fn miller_rabin_rounds(
    certainty: u32,
    bit_length: usize,
    randomly_selected: bool,
) -> u32 {
    let mut rounds = certainty.div_ceil(2).max(1);
    if randomly_selected {
        // Bouncy Castle reduces the 100-bit-certainty baseline for candidates
        // drawn uniformly at random. Its bound is stronger for this specific
        // prime-generation case than for testing an arbitrary caller value.
        let rounds_for_100 = match bit_length {
            1024.. => 4,
            512.. => 8,
            256.. => 16,
            _ => 50,
        };
        rounds = if certainty < 100 {
            rounds.min(rounds_for_100)
        } else {
            rounds - 50 + rounds_for_100
        };
    }
    rounds
}

pub(super) fn fixed_is_probable_prime<const N: usize, R: Rng + ?Sized>(
    value: &FixedBigUint<N>,
    certainty: u32,
    randomly_selected: bool,
    rng: &mut R,
) -> bool {
    if certainty == 0 {
        return true;
    }

    let two = fixed_small(2);
    let three = fixed_small(3);
    if value < &two {
        return false;
    }
    if value == &two || value == &three {
        return true;
    }
    if !value.test_bit(0) {
        return false;
    }
    if let Some(composite) = has_small_factor(value.as_limbs()) {
        return !composite;
    }

    let one = fixed_small(1);
    let n_minus_one = *value - one;
    let s = n_minus_one
        .lowest_set_bit()
        .expect("an odd value above three has a non-zero predecessor");
    let d = n_minus_one >> s;
    let witness_range = *value - fixed_small(3);
    let params = FixedMontyParams::new(Odd::new(*value).expect("candidate is odd"));

    'witness: for _ in 0..miller_rabin_rounds(certainty, value.bit_length(), randomly_selected) {
        let witness = random_fixed_below(&witness_range, rng) + two;
        let mut result = FixedMontyForm::new(&witness, params).pow(&d);
        let mut residue = result.retrieve();
        if residue == one || residue == n_minus_one {
            continue;
        }
        for _ in 1..s {
            result = result.square();
            residue = result.retrieve();
            if residue == n_minus_one {
                continue 'witness;
            }
            if residue == one {
                return false;
            }
        }
        return false;
    }
    true
}

#[cfg(feature = "alloc")]
pub(super) fn big_uint_is_probable_prime<R: Rng + ?Sized>(
    value: &BigUint,
    certainty: u32,
    randomly_selected: bool,
    rng: &mut R,
) -> bool {
    if certainty == 0 {
        return true;
    }

    let two = BigUint::from(2_u8);
    let three = BigUint::from(3_u8);
    if value < &two {
        return false;
    }
    if value == &two || value == &three {
        return true;
    }
    if !value.test_bit(0) {
        return false;
    }
    if let Some(composite) = has_small_factor(value.as_limbs()) {
        return !composite;
    }

    let one = BigUint::from(1_u8);
    let n_minus_one = value - &one;
    let s = n_minus_one
        .lowest_set_bit()
        .expect("an odd value above three has a non-zero predecessor");
    let d = &n_minus_one >> s;
    let witness_range = value - &BigUint::from(3_u8);
    let params = MontyParams::new(Odd::new(value.clone()).expect("candidate is odd"));

    'witness: for _ in 0..miller_rabin_rounds(certainty, value.bits(), randomly_selected) {
        let witness = random_big_uint_below(&witness_range, rng) + &two;
        let mut result = MontyForm::new(&witness, params.clone()).pow(&d);
        let mut residue = result.retrieve();
        if residue == one || residue == n_minus_one {
            continue;
        }
        for _ in 1..s {
            result = result.square();
            residue = result.retrieve();
            if residue == n_minus_one {
                continue 'witness;
            }
            if residue == one {
                return false;
            }
        }
        return false;
    }
    true
}
