//! Modular exponentiation over dynamic and fixed-width limbs.

#[cfg(feature = "alloc")]
use alloc::{vec, vec::Vec};

use super::exponentiation_window;
#[cfg(feature = "alloc")]
use super::mul::montgomery_mul;
use super::mul::{
    fixed_add_mod, fixed_montgomery_mul, fixed_mul_mod, fixed_one_mod, montgomery_inverse,
};
#[cfg(feature = "alloc")]
use crate::arithmetic::{bit_len, div_rem, mul, significant_len, square};
use crate::arithmetic::{fixed_bit_len, fixed_div_rem, fixed_test_bit};
use crate::{Limb, Word};

/// Computes modular exponentiation with Montgomery multiplication when the
/// modulus is odd and falls back to division-based reduction when it is even.
#[cfg(feature = "alloc")]
pub(crate) fn mod_pow(value: &[Limb], exponent: &[Limb], modulus: &[Limb]) -> Vec<Limb> {
    assert!(significant_len(modulus) != 0, "modulus must be non-zero");
    if modulus[0].0 & 1 == 0 {
        return division_mod_pow(value, exponent, modulus);
    }

    let modulus_len = significant_len(modulus);
    let modulus = &modulus[..modulus_len];
    if modulus_len == 1 && modulus[0].0 == 1 {
        return Vec::new();
    }

    let inverse = montgomery_inverse(modulus[0].0);
    let mut radix = vec![Limb(0); modulus_len + 1];
    radix[modulus_len] = Limb(1);
    let radix = div_rem(&radix, modulus).1;
    let radix_squared = div_rem(&square(&radix), modulus).1;
    let base = montgomery_mul(&div_rem(value, modulus).1, &radix_squared, modulus, inverse);
    let exponent_bits = bit_len(exponent);
    if exponent_bits == 0 {
        return radix;
    }

    let window = exponentiation_window(exponent_bits);
    let table_len = 1 << (window - 1);
    let mut odd_powers = Vec::with_capacity(table_len);
    odd_powers.push(base.clone());
    if table_len > 1 {
        let base_squared = montgomery_mul(&base, &base, modulus, inverse);
        for index in 1..table_len {
            odd_powers.push(montgomery_mul(
                &odd_powers[index - 1],
                &base_squared,
                modulus,
                inverse,
            ));
        }
    }

    let mut result = radix;
    let mut remaining_bits = exponent_bits;
    while remaining_bits != 0 {
        let high = remaining_bits - 1;
        if !test_bit(exponent, high) {
            result = montgomery_mul(&result, &result, modulus, inverse);
            remaining_bits -= 1;
            continue;
        }

        let mut low = remaining_bits.saturating_sub(window);
        while !test_bit(exponent, low) {
            low += 1;
        }
        let mut window_value = 0_usize;
        for bit in (low..=high).rev() {
            window_value = (window_value << 1) | usize::from(test_bit(exponent, bit));
        }
        for _ in low..=high {
            result = montgomery_mul(&result, &result, modulus, inverse);
        }
        result = montgomery_mul(&result, &odd_powers[window_value >> 1], modulus, inverse);
        remaining_bits = low;
    }

    montgomery_mul(&result, &[Limb(1)], modulus, inverse)
}

#[cfg(feature = "alloc")]
fn division_mod_pow(value: &[Limb], exponent: &[Limb], modulus: &[Limb]) -> Vec<Limb> {
    let mut result = div_rem(&[Limb(1)], modulus).1;
    let exponent_bits = bit_len(exponent);
    if exponent_bits == 0 {
        return result;
    }

    let base = div_rem(value, modulus).1;
    let window = exponentiation_window(exponent_bits);
    let table_len = 1 << (window - 1);
    let mut odd_powers = Vec::with_capacity(table_len);
    odd_powers.push(base.clone());
    if table_len > 1 {
        let base_squared = div_rem(&square(&base), modulus).1;
        for index in 1..table_len {
            odd_powers.push(div_rem(&mul(&odd_powers[index - 1], &base_squared), modulus).1);
        }
    }

    let mut remaining_bits = exponent_bits;
    while remaining_bits != 0 {
        let high = remaining_bits - 1;
        if !test_bit(exponent, high) {
            result = div_rem(&square(&result), modulus).1;
            remaining_bits -= 1;
            continue;
        }

        let mut low = remaining_bits.saturating_sub(window);
        while !test_bit(exponent, low) {
            low += 1;
        }
        let mut window_value = 0_usize;
        for bit in (low..=high).rev() {
            window_value = (window_value << 1) | usize::from(test_bit(exponent, bit));
        }
        for _ in low..=high {
            result = div_rem(&square(&result), modulus).1;
        }
        result = div_rem(&mul(&result, &odd_powers[window_value >> 1]), modulus).1;
        remaining_bits = low;
    }
    result
}

#[cfg(feature = "alloc")]
fn test_bit(words: &[Limb], index: usize) -> bool {
    words
        .get(index / Word::BITS as usize)
        .is_some_and(|word| word.0 >> (index % Word::BITS as usize) & 1 != 0)
}

pub(crate) fn fixed_mod_pow<const N: usize>(
    value: &[Limb; N],
    exponent: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    assert!(
        !crate::arithmetic::fixed_is_zero(modulus),
        "modulus must be non-zero"
    );
    if modulus[0].0 & 1 == 1 {
        return fixed_montgomery_mod_pow(value, exponent, modulus);
    }
    fixed_division_mod_pow(value, exponent, modulus)
}

fn fixed_division_mod_pow<const N: usize>(
    value: &[Limb; N],
    exponent: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let mut result = fixed_one_mod(modulus);
    let exponent_bits = fixed_bit_len(exponent);
    if exponent_bits == 0 {
        return result;
    }

    let base = fixed_div_rem(value, modulus).1;
    let window = exponentiation_window(exponent_bits);
    if window == 1 {
        for bit in (0..exponent_bits).rev() {
            result = fixed_mul_mod(&result, &result, modulus);
            if fixed_test_bit(exponent, bit) {
                result = fixed_mul_mod(&result, &base, modulus);
            }
        }
        return result;
    }

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

fn fixed_montgomery_mod_pow<const N: usize>(
    value: &[Limb; N],
    exponent: &[Limb; N],
    modulus: &[Limb; N],
) -> [Limb; N] {
    let one = fixed_one_mod(modulus);
    let exponent_bits = fixed_bit_len(exponent);
    if exponent_bits == 0 {
        return one;
    }

    let inverse = montgomery_inverse(modulus[0].0);
    let mut radix = one;
    for _ in 0..N * Word::BITS as usize {
        radix = fixed_add_mod(&radix, &radix, modulus);
    }
    let mut radix_squared = radix;
    for _ in 0..N * Word::BITS as usize {
        radix_squared = fixed_add_mod(&radix_squared, &radix_squared, modulus);
    }

    let reduced = fixed_div_rem(value, modulus).1;
    let base = fixed_montgomery_mul(&reduced, &radix_squared, modulus, inverse);
    let mut result = radix;
    let window = exponentiation_window(exponent_bits);
    if window == 1 {
        for bit in (0..exponent_bits).rev() {
            result = fixed_montgomery_mul(&result, &result, modulus, inverse);
            if fixed_test_bit(exponent, bit) {
                result = fixed_montgomery_mul(&result, &base, modulus, inverse);
            }
        }
        return fixed_montgomery_mul(&result, &one, modulus, inverse);
    }

    let table_len = 1 << (window - 1);
    let mut odd_powers = [[Limb(0); N]; 16];
    odd_powers[0] = base;
    let base_squared = fixed_montgomery_mul(&base, &base, modulus, inverse);
    for index in 1..table_len {
        odd_powers[index] =
            fixed_montgomery_mul(&odd_powers[index - 1], &base_squared, modulus, inverse);
    }

    let mut remaining_bits = exponent_bits;
    while remaining_bits != 0 {
        let high = remaining_bits - 1;
        if !fixed_test_bit(exponent, high) {
            result = fixed_montgomery_mul(&result, &result, modulus, inverse);
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
            result = fixed_montgomery_mul(&result, &result, modulus, inverse);
        }
        result = fixed_montgomery_mul(&result, &odd_powers[window_value >> 1], modulus, inverse);
        remaining_bits = low;
    }

    fixed_montgomery_mul(&result, &one, modulus, inverse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::{fixed_is_zero, fixed_shr_one};

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

    #[cfg(feature = "alloc")]
    #[test]
    fn montgomery_modular_power_matches_division_reduction_for_random_limbs() {
        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        let mut state = 0x1319_8a2e_0370_7344_u64;
        for case in 0..600 {
            let len = next_word(&mut state) as usize % 8 + 1;
            let mut value = (0..len)
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();
            let exponent = (0..(len.min(3)))
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();
            let mut modulus = (0..len)
                .map(|_| Limb(next_word(&mut state)))
                .collect::<Vec<_>>();
            modulus[0].0 |= 1;
            modulus[len - 1].0 |= 1;
            if modulus.len() == 1 && modulus[0].0 == 1 {
                modulus[0].0 = 3;
            }
            if case % 3 == 0 {
                value.push(Limb(next_word(&mut state)));
            }

            assert_eq!(
                mod_pow(&value, &exponent, &modulus),
                division_mod_pow(&value, &exponent, &modulus),
                "case {case}"
            );
        }

        assert_eq!(mod_pow(&[Limb(7)], &[Limb(13)], &[Limb(10)]), vec![Limb(7)]);
        assert_eq!(mod_pow(&[Limb(7)], &[], &[Limb(1)]), Vec::<Limb>::new());
    }

    #[test]
    fn fixed_montgomery_power_matches_division_reduction_for_random_limbs() {
        type Wide = [Limb; 4];

        fn next_word(state: &mut u64) -> Word {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state as Word
        }

        let mut state = 0x082e_fa98_ec4e_6c89_u64;
        for case in 0..200 {
            let value: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            let mut exponent = [Limb(0); 4];
            exponent[0] = Limb(next_word(&mut state));
            let mut modulus: Wide = core::array::from_fn(|_| Limb(next_word(&mut state)));
            modulus[0].0 |= 1;
            modulus[3].0 |= 1;

            assert_eq!(
                fixed_montgomery_mod_pow(&value, &exponent, &modulus),
                fixed_division_mod_pow(&value, &exponent, &modulus),
                "case {case}"
            );
        }

        assert_eq!(
            fixed_mod_pow(
                &[Limb(7), Limb(0)],
                &[Limb(13), Limb(0)],
                &[Limb(10), Limb(0)]
            ),
            [Limb(7), Limb(0)]
        );
    }
}
