//! Original fixed-width regression tests; adapters exist only in tests, preserving assertions and expected values.
pub(crate) fn fixed_cmp<const N: usize>(arg0: &[Limb; N], arg1: &[Limb; N]) -> Ordering {
    crate::LimbArray::new(*(arg0)).cmp(&crate::LimbArray::new(*(arg1)))
}
pub(crate) fn fixed_add<const N: usize>(arg0: &[Limb; N], arg1: &[Limb; N]) -> ([Limb; N], bool) {
    {
        let (value, overflow) = crate::LimbArray::new(*(arg0)).add(&crate::LimbArray::new(*(arg1)));
        (value.into_limbs(), overflow)
    }
}
pub(crate) fn fixed_sub<const N: usize>(arg0: &[Limb; N], arg1: &[Limb; N]) -> ([Limb; N], bool) {
    {
        let (value, overflow) = crate::LimbArray::new(*(arg0)).sub(&crate::LimbArray::new(*(arg1)));
        (value.into_limbs(), overflow)
    }
}
pub(crate) fn fixed_mul<const N: usize>(arg0: &[Limb; N], arg1: &[Limb; N]) -> ([Limb; N], bool) {
    {
        let (value, overflow) = crate::LimbArray::new(*(arg0)).mul(&crate::LimbArray::new(*(arg1)));
        (value.into_limbs(), overflow)
    }
}
pub(crate) fn fixed_mul_wide<const N: usize>(
    arg0: &[Limb; N],
    arg1: &[Limb; N],
) -> ([Limb; N], [Limb; N]) {
    {
        let (low, high) = crate::LimbArray::new(*(arg0)).mul_wide(&crate::LimbArray::new(*(arg1)));
        (low.into_limbs(), high.into_limbs())
    }
}
pub(crate) fn fixed_square_wide<const N: usize>(arg0: &[Limb; N]) -> ([Limb; N], [Limb; N]) {
    {
        let (low, high) = crate::LimbArray::new(*(arg0)).square_wide();
        (low.into_limbs(), high.into_limbs())
    }
}
pub(crate) fn fixed_mul_add_to<const N: usize>(
    arg0: &[Limb; N],
    arg1: &[Limb; N],
    arg2: &mut [Limb; N],
    arg3: &mut [Limb; N],
) -> bool {
    {
        let low = arg2;
        let high = arg3;
        let mut low_value = crate::LimbArray::new(*low);
        let mut high_value = crate::LimbArray::new(*high);
        let overflow = crate::LimbArray::new(*(arg0)).mul_add_to(
            &crate::LimbArray::new(*(arg1)),
            &mut low_value,
            &mut high_value,
        );
        *low = low_value.into_limbs();
        *high = high_value.into_limbs();
        overflow
    }
}
pub(crate) fn fixed_div_rem<const N: usize>(
    arg0: &[Limb; N],
    arg1: &[Limb; N],
) -> ([Limb; N], [Limb; N]) {
    {
        let (low, high) = crate::LimbArray::new(*(arg0)).div_rem(&crate::LimbArray::new(*(arg1)));
        (low.into_limbs(), high.into_limbs())
    }
}
pub(crate) fn fixed_wide_rem<const N: usize>(
    arg0: &[Limb; N],
    arg1: &[Limb; N],
    arg2: &[Limb; N],
) -> [Limb; N] {
    crate::LimbArray::new(*(arg0))
        .wide_rem(
            &crate::LimbArray::new(*(arg1)),
            &crate::LimbArray::new(*(arg2)),
        )
        .into_limbs()
}
pub(crate) fn fixed_wrapping_neg<const N: usize>(arg0: &[Limb; N]) -> [Limb; N] {
    crate::LimbArray::new(*(arg0)).wrapping_neg().into_limbs()
}
pub(crate) fn fixed_gcd<const N: usize>(arg0: &[Limb; N], arg1: &[Limb; N]) -> [Limb; N] {
    crate::LimbArray::new(*(arg0))
        .gcd(&crate::LimbArray::new(*(arg1)))
        .into_limbs()
}
pub(crate) fn fixed_bit_len<const N: usize>(arg0: &[Limb; N]) -> usize {
    crate::LimbArray::new(*(arg0)).bit_len()
}
pub(crate) fn fixed_test_bit<const N: usize>(arg0: &[Limb; N], arg1: usize) -> bool {
    crate::LimbArray::new(*(arg0)).test_bit(arg1)
}
pub(crate) fn fixed_is_zero<const N: usize>(arg0: &[Limb; N]) -> bool {
    crate::LimbArray::new(*(arg0)).is_zero()
}
pub(crate) fn fixed_is_one<const N: usize>(arg0: &[Limb; N]) -> bool {
    crate::LimbArray::new(*(arg0)).is_one()
}
pub(crate) fn fixed_shr_one<const N: usize>(arg0: &mut [Limb; N]) {
    {
        let words = arg0;
        let mut value = crate::LimbArray::new(*words);
        value.shr_one();
        *words = value.into_limbs();
    }
}
pub(crate) fn fixed_shl_one<const N: usize>(arg0: &mut [Limb; N]) -> bool {
    {
        let words = arg0;
        let mut value = crate::LimbArray::new(*words);
        let shifted = value.shl_one();
        *words = value.into_limbs();
        shifted
    }
}
pub(crate) fn fixed_is_negative<const N: usize>(arg0: &[Limb; N]) -> bool {
    crate::FixedBigInt::is_negative_limbs(arg0)
}
pub(crate) fn fixed_abs<const N: usize>(arg0: &[Limb; N]) -> [Limb; N] {
    crate::FixedBigInt::from_limbs(*(arg0)).magnitude()
}
use super::*;

type Words = [Limb; 2];

#[test]
fn fixed_add_sub_mul_and_compare_cover_carry_borrow_and_overflow() {
    let one = [Limb::new(1), Limb::new(0)];
    let max = [Limb::new(Word::MAX), Limb::new(Word::MAX)];

    assert_eq!(fixed_cmp(&one, &max), Ordering::Less);
    assert_eq!(fixed_add(&one, &one), ([Limb::new(2), Limb::new(0)], false));
    assert_eq!(fixed_add(&max, &one), ([Limb::new(0), Limb::new(0)], true));
    assert_eq!(fixed_sub(&one, &one), ([Limb::new(0), Limb::new(0)], false));
    assert_eq!(
        fixed_sub(&[Limb::new(0), Limb::new(1)], &one),
        ([Limb::new(Word::MAX), Limb::new(0)], false)
    );
    assert!(fixed_sub(&[Limb::new(0), Limb::new(0)], &one).1);

    assert_eq!(
        fixed_mul(&[Limb::new(3), Limb::new(0)], &[Limb::new(7), Limb::new(0)]),
        ([Limb::new(21), Limb::new(0)], false)
    );
    assert!(fixed_mul(&max, &max).1);
}

#[test]
fn fixed_wide_multiplication_preserves_both_product_halves() {
    let lhs = [Limb::new(3), Limb::new(1)];
    let rhs = [Limb::new(5), Limb::new(1)];
    let (low, high) = fixed_mul_wide(&lhs, &rhs);
    assert_eq!(low, [Limb::new(15), Limb::new(8)]);
    assert_eq!(high, [Limb::new(1), Limb::new(0)]);
    assert_eq!(fixed_square_wide(&lhs), fixed_mul_wide(&lhs, &lhs));
}

#[test]
fn fixed_mul_add_to_propagates_carry_across_both_halves() {
    let lhs = [Limb::new(Word::MAX), Limb::new(Word::MAX)];
    let rhs = [Limb::new(1), Limb::new(0)];
    let mut low = [Limb::new(1), Limb::new(0)];
    let mut high = [Limb::new(7), Limb::new(0)];

    assert!(!fixed_mul_add_to(&lhs, &rhs, &mut low, &mut high));
    assert_eq!(low, [Limb::new(0), Limb::new(0)]);
    assert_eq!(high, [Limb::new(8), Limb::new(0)]);

    low = [Limb::new(1), Limb::new(0)];
    high = [Limb::new(Word::MAX), Limb::new(Word::MAX)];
    assert!(fixed_mul_add_to(&lhs, &rhs, &mut low, &mut high));
    assert_eq!(low, [Limb::new(0), Limb::new(0)]);
    assert_eq!(high, [Limb::new(0), Limb::new(0)]);
}

#[test]
fn fixed_wide_remainder_handles_a_full_width_modulus() {
    type Wide = [Limb; 4];

    let modulus: Wide = [Limb::new(Word::MAX); 4];
    let mut value = modulus;
    value[0] = Limb::new(Word::MAX - 1);
    let (low, high) = fixed_mul_wide(&value, &value);
    assert_eq!(
        fixed_wide_rem(&low, &high, &modulus),
        [Limb::new(1), Limb::new(0), Limb::new(0), Limb::new(0)]
    );

    let radix_low = [Limb::new(0); 4];
    let radix_high = [Limb::new(1), Limb::new(0), Limb::new(0), Limb::new(0)];
    assert_eq!(
        fixed_wide_rem(&radix_low, &radix_high, &modulus),
        [Limb::new(1), Limb::new(0), Limb::new(0), Limb::new(0)]
    );
}

#[test]
fn fixed_division_sign_and_gcd_helpers_cover_all_results() {
    let value: Words = [Limb::new(100), Limb::new(0)];
    let divisor: Words = [Limb::new(9), Limb::new(0)];
    assert_eq!(
        fixed_div_rem(&value, &divisor),
        ([Limb::new(11), Limb::new(0)], [Limb::new(1), Limb::new(0)])
    );

    let minus_one = [Limb::new(Word::MAX), Limb::new(Word::MAX)];
    assert!(fixed_is_negative(&minus_one));
    assert_eq!(fixed_wrapping_neg(&minus_one), [Limb::new(1), Limb::new(0)]);
    assert_eq!(fixed_abs(&minus_one), [Limb::new(1), Limb::new(0)]);
    assert_eq!(fixed_abs(&value), value);
    assert_eq!(
        fixed_gcd(
            &[Limb::new(48), Limb::new(0)],
            &[Limb::new(18), Limb::new(0)]
        ),
        [Limb::new(6), Limb::new(0)]
    );
}

#[test]
fn fixed_right_shift_helper_crosses_limb_boundaries() {
    let mut value = [Limb::new(0), Limb::new(1)];
    fixed_shr_one(&mut value);
    assert_eq!(value, [Limb::new(1 << (Word::BITS - 1)), Limb::new(0)]);
}

#[test]
fn fixed_left_shift_helper_crosses_limb_boundaries_and_reports_carry() {
    let mut value = [Limb::new(Word::MAX), Limb::new(1 << (Word::BITS - 1))];
    assert!(fixed_shl_one(&mut value));
    assert_eq!(value, [Limb::new(Word::MAX - 1), Limb::new(1)]);
}

#[test]
#[should_panic(expected = "attempted to divide by zero")]
fn fixed_division_rejects_zero() {
    let _ = fixed_div_rem(&[Limb::new(1)], &[Limb::new(0)]);
}

#[cfg(feature = "alloc")]
#[test]
fn dynamic_normalization_and_comparison_are_directly_covered() {
    let mut words = vec![Limb::new(1), Limb::new(0), Limb::new(0)];
    normalize(&mut words);
    assert_eq!(words, [Limb::new(1)]);
    assert_eq!(significant_len(&[Limb::new(1), Limb::new(0)]), 1);
    assert_eq!(
        cmp(&[Limb::new(1), Limb::new(0)], &[Limb::new(2)]),
        Ordering::Less
    );
}

#[cfg(feature = "alloc")]
#[test]
fn optimized_square_matches_independent_multiplication_for_multi_limb_values() {
    let cases = [
        vec![],
        vec![Limb::new(1)],
        vec![Limb::new(Word::MAX)],
        vec![Limb::new(3), Limb::new(5)],
        vec![Limb::new(Word::MAX), Limb::new(Word::MAX)],
        vec![Limb::new(0), Limb::new(1), Limb::new(7)],
        vec![
            Limb::new(Word::MAX),
            Limb::new(0),
            Limb::new(Word::MAX),
            Limb::new(17),
        ],
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
        let mut words = (0..len)
            .map(|_| Limb::new(next_word(state)))
            .collect::<Vec<_>>();
        words[len - 1] = Limb::new(words[len - 1].to_word() | (1));
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
    let lhs = vec![Limb::new(Word::MAX); KARATSUBA_THRESHOLD];
    let mut rhs = lhs.clone();
    rhs[KARATSUBA_THRESHOLD / 2] = Limb::new(Word::MAX - 1);

    assert_eq!(mul(&lhs, &rhs), schoolbook_mul(&lhs, &rhs));
    assert_eq!(square(&lhs), schoolbook_square(&lhs));
    assert_eq!(square(&lhs), mul(&lhs, &lhs.clone()));

    let mut sparse = vec![Limb::new(0); KARATSUBA_THRESHOLD];
    sparse[KARATSUBA_THRESHOLD / 2] = Limb::new(3);
    sparse[KARATSUBA_THRESHOLD - 1] = Limb::new(1);
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
            .map(|_| Limb::new(next_word(&mut state)))
            .collect::<Vec<_>>();
        let mut divisor = (0..divisor_len)
            .map(|_| Limb::new(next_word(&mut state)))
            .collect::<Vec<_>>();
        dividend[dividend_len - 1] = Limb::new(dividend[dividend_len - 1].to_word() | (1));
        divisor[divisor_len - 1] = Limb::new(divisor[divisor_len - 1].to_word() | (1));

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
        power_of_two_shift(&[Limb::new(0), Limb::new(8)]),
        Some(Word::BITS as usize + 3)
    );
    assert_eq!(power_of_two_shift(&[Limb::new(3)]), None);
    assert_eq!(power_of_two_shift(&[]), None);
    assert_eq!(mul(&[], &[Limb::new(2)]), []);
    assert_eq!(mul(&[Limb::new(8)], &[Limb::new(7)]), [Limb::new(56)]);
    assert_eq!(mul(&[Limb::new(3)], &[Limb::new(7)]), [Limb::new(21)]);
    assert_eq!(
        mul(&[Limb::new(0), Limb::new(1)], &[Limb::new(0), Limb::new(1)]),
        [Limb::new(0), Limb::new(0), Limb::new(1)]
    );
}

#[cfg(feature = "alloc")]
#[test]
fn division_covers_small_word_multi_word_less_equal_and_exact_cases() {
    assert_eq!(
        div_rem(&[Limb::new(100)], &[Limb::new(9)]),
        (vec![Limb::new(11)], vec![Limb::new(1)])
    );
    assert_eq!(
        div_rem(&[Limb::new(2)], &[Limb::new(3), Limb::new(1)]),
        (vec![], vec![Limb::new(2)])
    );
    assert_eq!(
        div_rem(&[Limb::new(4), Limb::new(2)], &[Limb::new(4), Limb::new(2)]),
        (vec![Limb::new(1)], vec![])
    );

    let dividend = [Limb::new(5), Limb::new(9), Limb::new(2)];
    let divisor = [Limb::new(7), Limb::new(1)];
    let (quotient, remainder) = div_rem(&dividend, &divisor);
    let reconstructed = crate::BigUint::from_limbs(mul(&quotient, &divisor))
        + crate::BigUint::from_limbs(remainder.clone());
    assert_eq!(reconstructed.as_limbs(), dividend);
    assert_eq!(cmp(&remainder, &divisor), Ordering::Less);
}

#[cfg(feature = "alloc")]
#[test]
fn shifts_and_truncation_checks_cover_word_and_bit_boundaries() {
    let value = [Limb::new(1), Limb::new(2)];
    assert_eq!(shl(&value, 0), value);
    assert_eq!(
        shl(&value, Word::BITS as usize),
        [Limb::new(0), Limb::new(1), Limb::new(2)]
    );
    assert_eq!(shr(&value, Word::BITS as usize), [Limb::new(2)]);
    assert_eq!(shr(&value, 2 * Word::BITS as usize), []);
    assert!(truncated_bits_are_nonzero(&[Limb::new(1), Limb::new(2)], 1));
    assert!(!truncated_bits_are_nonzero(&[Limb::new(2)], 1));
    assert_eq!(
        bit_len(&[Limb::new(0), Limb::new(8)]),
        Word::BITS as usize + 4
    );
    assert_eq!(bit_len(&[]), 0);
}

#[cfg(feature = "alloc")]
#[test]
fn small_arithmetic_and_parsing_helpers_are_covered() {
    let mut words = vec![Limb::new(Word::MAX)];
    add_small(&mut words, 1);
    assert_eq!(words, [Limb::new(0), Limb::new(1)]);
    mul_small(&mut words, 3);
    assert_eq!(words, [Limb::new(0), Limb::new(3)]);
    mul_small(&mut words, 0);
    assert!(words.is_empty());

    assert_eq!(parse_unsigned("+FF", 16), Ok((false, vec![Limb::new(255)])));
    assert_eq!(parse_unsigned("-10", 10), Ok((true, vec![Limb::new(10)])));
    assert_eq!(parse_unsigned("-0", 10), Ok((false, vec![])));
    assert_eq!(parse_unsigned("?", 10), Err(ParseBigIntError::InvalidDigit));

    let mut quotient = vec![Limb::new(100)];
    assert_eq!(div_rem_small(&mut quotient, 9), 1);
    assert_eq!(quotient, [Limb::new(11)]);
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
            .map(|_| Limb::new(next_word(&mut state)))
            .collect::<Vec<_>>();
        let mut divisor = (0..divisor_len)
            .map(|_| Limb::new(next_word(&mut state)))
            .collect::<Vec<_>>();

        // Exercise normalization and quotient-estimate edge cases as well
        // as uniformly generated words.
        match case % 4 {
            0 => divisor[divisor_len - 1] = Limb::new(1),
            1 => divisor[divisor_len - 1] = Limb::new(Word::MAX),
            2 => dividend[dividend_len - 1] = Limb::new(Word::MAX),
            _ => {}
        }
        if divisor.iter().all(|word| word.to_word() == 0) {
            divisor[0] = Limb::new(1);
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
        let mut dividend: Wide = core::array::from_fn(|_| Limb::new(next_word(&mut state)));
        let mut divisor: Wide = core::array::from_fn(|_| Limb::new(next_word(&mut state)));
        let divisor_len = next_word(&mut state) as usize % divisor.len() + 1;
        divisor[divisor_len..].fill(Limb::new(0));
        match case % 3 {
            0 => divisor[divisor_len - 1] = Limb::new(1),
            1 => divisor[divisor_len - 1] = Limb::new(Word::MAX),
            _ => {}
        }
        if divisor.iter().all(|word| word.to_word() == 0) {
            divisor[0] = Limb::new(1);
        }
        if case % 5 == 0 {
            let dividend_len = next_word(&mut state) as usize % dividend.len() + 1;
            dividend[dividend_len..].fill(Limb::new(0));
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
        let low: Wide = core::array::from_fn(|_| Limb::new(next_word(&mut state)));
        let high: Wide = core::array::from_fn(|_| Limb::new(next_word(&mut state)));
        let mut modulus: Wide = core::array::from_fn(|_| Limb::new(next_word(&mut state)));
        let modulus_len = next_word(&mut state) as usize % modulus.len() + 1;
        modulus[modulus_len..].fill(Limb::new(0));
        match case % 4 {
            0 => modulus[modulus_len - 1] = Limb::new(1),
            1 => modulus[modulus_len - 1] = Limb::new(Word::MAX),
            2 => modulus = [Limb::new(Word::MAX); 4],
            _ => {}
        }
        if modulus.iter().all(|word| word.to_word() == 0) {
            modulus[0] = Limb::new(1);
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
