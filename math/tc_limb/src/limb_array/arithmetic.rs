//! 從 tc_bigint 複製的固定寬度核心；僅供同長度型別的方法使用。
use super::LimbArray;
use crate::{Limb, WideWord, Word};
use core::cmp::Ordering;

impl<const N: usize> LimbArray<N> {
    pub(super) fn cmp_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> Ordering {
        lhs.iter().rev().cmp(rhs.iter().rev())
    }

    pub(super) fn add_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
        let mut result = [Limb::new(0); N];
        let mut carry = Limb::new(0);
        for index in 0..N {
            (result[index], carry) = lhs[index].carrying_add(rhs[index], carry);
        }
        (result, carry.to_word() != 0)
    }

    pub(super) fn sub_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
        let mut result = [Limb::new(0); N];
        let mut borrow = Limb::new(0);
        for index in 0..N {
            (result[index], borrow) = lhs[index].borrowing_sub(rhs[index], borrow);
        }
        (result, borrow.to_word() != 0)
    }

    pub(super) fn mul_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
        let mut result = [Limb::new(0); N];
        let mut overflow = false;

        for (left_index, left) in lhs.iter().enumerate() {
            let mut carry = 0 as Word;
            for (right_index, right) in rhs.iter().enumerate() {
                let index = left_index + right_index;
                if index >= N {
                    overflow |= left.to_word() != 0 && right.to_word() != 0;
                    continue;
                }
                let wide = left.to_word() as WideWord * right.to_word() as WideWord
                    + result[index].to_word() as WideWord
                    + carry as WideWord;
                result[index] = Limb::new(wide as Word);
                carry = (wide >> Word::BITS) as Word;
            }
            overflow |= carry != 0;
        }

        (result, overflow)
    }

    #[inline]
    pub(super) fn mul_wide_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], [Limb; N]) {
        let mut low = [Limb::new(0); N];
        let mut high = [Limb::new(0); N];

        for (left_index, left) in lhs.iter().enumerate() {
            let mut carry = 0 as Word;
            for (right_index, right) in rhs.iter().enumerate() {
                let index = left_index + right_index;
                let current = if index < N {
                    low[index].to_word()
                } else {
                    high[index - N].to_word()
                };
                let wide = left.to_word() as WideWord * right.to_word() as WideWord
                    + current as WideWord
                    + carry as WideWord;
                let output = Limb::new(wide as Word);
                if index < N {
                    low[index] = output;
                } else {
                    high[index - N] = output;
                }
                carry = (wide >> Word::BITS) as Word;
            }
            if N != 0 {
                high[left_index] = Limb::new(carry);
            }
        }

        (low, high)
    }
    #[inline]
    pub(super) fn square_wide_words(value: &[Limb; N]) -> ([Limb; N], [Limb; N]) {
        Self::mul_wide_words(value, value)
    }
    pub(super) fn mul_add_to_words(
        lhs: &[Limb; N],
        rhs: &[Limb; N],
        low: &mut [Limb; N],
        high: &mut [Limb; N],
    ) -> bool {
        let (product_low, product_high) = Self::mul_wide_words(lhs, rhs);
        let (next_low, low_overflow) = Self::add_words(low, &product_low);
        let (mut next_high, high_overflow) = Self::add_words(high, &product_high);
        let mut overflow = high_overflow;

        if low_overflow {
            let mut carry = Limb::new(1);
            for word in &mut next_high {
                (*word, carry) = word.carrying_add(Limb::new(0), carry);
            }
            overflow |= carry.to_word() != 0;
        }

        *low = next_low;
        *high = next_high;
        overflow
    }

    pub(super) fn div_rem_words(
        dividend: &[Limb; N],
        divisor: &[Limb; N],
    ) -> ([Limb; N], [Limb; N]) {
        let dividend_len = Self::significant_len(dividend);
        let divisor_len = Self::significant_len(divisor);
        assert!(divisor_len != 0, "attempted to divide by zero");

        let mut quotient = [Limb::new(0); N];
        if dividend_len < divisor_len || Self::cmp_words(dividend, divisor) == Ordering::Less {
            return (quotient, *dividend);
        }

        if divisor_len == 1 {
            let divisor = divisor[0].to_word() as WideWord;
            let mut remainder = 0 as WideWord;
            for index in (0..dividend_len).rev() {
                let wide = (remainder << Word::BITS) | dividend[index].to_word() as WideWord;
                quotient[index] = Limb::new((wide / divisor) as Word);
                remainder = wide % divisor;
            }
            let mut remainder_words = [Limb::new(0); N];
            remainder_words[0] = Limb::new(remainder as Word);
            return (quotient, remainder_words);
        }

        let normalization_shift = divisor[divisor_len - 1].to_word().leading_zeros() as usize;
        let mut normalized_divisor = [Limb::new(0); N];
        let divisor_carry = Self::shl_words(
            divisor,
            divisor_len,
            normalization_shift,
            &mut normalized_divisor,
        );
        debug_assert_eq!(divisor_carry, 0);

        let mut normalized_dividend = [Limb::new(0); N];
        let mut dividend_extra = Self::shl_words(
            dividend,
            dividend_len,
            normalization_shift,
            &mut normalized_dividend,
        );
        if dividend_len < N {
            normalized_dividend[dividend_len] = Limb::new(dividend_extra);
            dividend_extra = 0;
        }

        let quotient_len = dividend_len - divisor_len + 1;
        let base = (1 as WideWord) << Word::BITS;
        let divisor_high = normalized_divisor[divisor_len - 1].to_word() as WideWord;

        for offset in (0..quotient_len).rev() {
            let numerator =
                ((Self::word_at(&normalized_dividend, dividend_extra, offset + divisor_len)
                    as WideWord)
                    << Word::BITS)
                    | normalized_dividend[offset + divisor_len - 1].to_word() as WideWord;
            let mut estimate = numerator / divisor_high;
            let mut estimate_remainder = numerator % divisor_high;
            let divisor_next = normalized_divisor[divisor_len - 2].to_word() as WideWord;
            let dividend_next = normalized_dividend[offset + divisor_len - 2].to_word() as WideWord;
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
            let high = Self::word_at(&normalized_dividend, dividend_extra, high_index);
            let (difference, negative) = high.overflowing_sub(borrow as Word);
            Self::set_word_at(
                &mut normalized_dividend,
                &mut dividend_extra,
                high_index,
                difference,
            );
            if negative {
                estimate -= 1;
                let mut carry = Limb::new(0);
                for index in 0..divisor_len {
                    (normalized_dividend[offset + index], carry) = normalized_dividend
                        [offset + index]
                        .carrying_add(normalized_divisor[index], carry);
                }
                let high = Self::word_at(&normalized_dividend, dividend_extra, high_index);
                Self::set_word_at(
                    &mut normalized_dividend,
                    &mut dividend_extra,
                    high_index,
                    high.wrapping_add(carry.to_word()),
                );
            }
            quotient[offset] = Limb::new(estimate as Word);
        }

        let mut remainder = [Limb::new(0); N];
        if normalization_shift == 0 {
            remainder[..divisor_len].copy_from_slice(&normalized_dividend[..divisor_len]);
        } else {
            for index in 0..divisor_len {
                let high = if index + 1 < divisor_len {
                    normalized_dividend[index + 1].to_word()
                } else {
                    0
                };
                remainder[index] = Limb::new(
                    (normalized_dividend[index].to_word() >> normalization_shift)
                        | (high << (Word::BITS as usize - normalization_shift)),
                );
            }
        }
        (quotient, remainder)
    }

    #[inline]
    pub(super) fn wide_rem_words(
        low: &[Limb; N],
        high: &[Limb; N],
        modulus: &[Limb; N],
    ) -> [Limb; N] {
        let modulus_len = Self::significant_len(modulus);
        assert!(modulus_len != 0, "attempted to divide by zero");

        let high_len = Self::significant_len(high);
        if high_len == 0 {
            return Self::div_rem_words(low, modulus).1;
        }

        if modulus_len == 1 {
            let divisor = modulus[0].to_word() as WideWord;
            let mut remainder = 0 as WideWord;
            for word in high.iter().rev().chain(low.iter().rev()) {
                let wide = (remainder << Word::BITS) | word.to_word() as WideWord;
                remainder = wide % divisor;
            }
            let mut result = [Limb::new(0); N];
            result[0] = Limb::new(remainder as Word);
            return result;
        }

        let normalization_shift = modulus[modulus_len - 1].to_word().leading_zeros() as usize;
        let mut normalized_modulus = [Limb::new(0); N];
        let modulus_carry = Self::shl_words(
            modulus,
            modulus_len,
            normalization_shift,
            &mut normalized_modulus,
        );
        debug_assert_eq!(modulus_carry, 0);
        // 逐字處理正規化的雙寬度被除數，只保留目前餘數視窗，避免配置 2N 陣列。
        let input_len = N + high_len;
        let mut remainder = [Limb::new(0); N];
        let base = (1 as WideWord) << Word::BITS;
        let modulus_high = normalized_modulus[modulus_len - 1].to_word() as WideWord;
        let modulus_next = normalized_modulus[modulus_len - 2].to_word() as WideWord;
        // 最高的 modulus_len 個字形成小於模數的前綴，作為滾動餘數的初值。
        let first_quotient_input = input_len + 1 - modulus_len;
        for (index, word) in remainder.iter_mut().take(modulus_len).enumerate() {
            *word = Limb::new(Self::normalized_wide_word(
                low,
                high,
                first_quotient_input + index,
                normalization_shift,
            ));
        }
        debug_assert_eq!(
            Self::cmp_words(&remainder, &normalized_modulus),
            Ordering::Less
        );

        for input_index in (0..first_quotient_input).rev() {
            let input_word =
                Self::normalized_wide_word(low, high, input_index, normalization_shift);
            let mut window_high = remainder[modulus_len - 1].to_word();
            for index in (1..modulus_len).rev() {
                remainder[index] = remainder[index - 1];
            }
            remainder[0] = Limb::new(input_word);

            let numerator = ((window_high as WideWord) << Word::BITS)
                | remainder[modulus_len - 1].to_word() as WideWord;
            let mut estimate = numerator / modulus_high;
            let mut estimate_remainder = numerator % modulus_high;
            let dividend_next = remainder[modulus_len - 2].to_word() as WideWord;
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
                let product = estimate_word as WideWord
                    * normalized_modulus[index].to_word() as WideWord
                    + borrow;
                let (difference, underflow) =
                    remainder[index].to_word().overflowing_sub(product as Word);
                remainder[index] = Limb::new(difference);
                borrow = (product >> Word::BITS) + underflow as WideWord;
            }

            let (difference, negative) = window_high.overflowing_sub(borrow as Word);
            window_high = difference;
            if negative {
                let mut carry = Limb::new(0);
                for index in 0..modulus_len {
                    (remainder[index], carry) =
                        remainder[index].carrying_add(normalized_modulus[index], carry);
                }
                window_high = window_high.wrapping_add(carry.to_word());
            }
            debug_assert_eq!(window_high, 0);
        }

        if normalization_shift != 0 {
            for index in 0..modulus_len {
                let high = if index + 1 < modulus_len {
                    remainder[index + 1].to_word()
                } else {
                    0
                };
                remainder[index] = Limb::new(
                    (remainder[index].to_word() >> normalization_shift)
                        | (high << (Word::BITS as usize - normalization_shift)),
                );
            }
        }
        remainder
    }

    #[inline(always)]
    fn normalized_wide_word(low: &[Limb; N], high: &[Limb; N], index: usize, shift: usize) -> Word {
        let current = Self::wide_word(low, high, index);
        if shift == 0 {
            return current;
        }
        let previous = index
            .checked_sub(1)
            .map_or(0, |previous| Self::wide_word(low, high, previous));
        (current << shift) | (previous >> (Word::BITS as usize - shift))
    }

    #[inline(always)]
    fn wide_word(low: &[Limb; N], high: &[Limb; N], index: usize) -> Word {
        if index < N {
            low[index].to_word()
        } else {
            high.get(index - N).map_or(0, |word| word.to_word())
        }
    }

    fn significant_len(words: &[Limb; N]) -> usize {
        words
            .iter()
            .rposition(|word| word.to_word() != 0)
            .map_or(0, |index| index + 1)
    }

    fn shl_words(input: &[Limb; N], len: usize, shift: usize, output: &mut [Limb; N]) -> Word {
        debug_assert!(shift < Word::BITS as usize);
        if shift == 0 {
            output[..len].copy_from_slice(&input[..len]);
            return 0;
        }

        let mut carry = 0 as Word;
        for index in 0..len {
            let wide = ((input[index].to_word() as WideWord) << shift) | carry as WideWord;
            output[index] = Limb::new(wide as Word);
            carry = (wide >> Word::BITS) as Word;
        }
        carry
    }

    fn word_at(words: &[Limb; N], extra: Word, index: usize) -> Word {
        if index < N {
            words[index].to_word()
        } else {
            debug_assert_eq!(index, N);
            extra
        }
    }

    pub(super) fn set_word_at(words: &mut [Limb; N], extra: &mut Word, index: usize, value: Word) {
        if index < N {
            words[index] = Limb::new(value);
        } else {
            debug_assert_eq!(index, N);
            *extra = value;
        }
    }

    pub(super) fn wrapping_neg_words(words: &[Limb; N]) -> [Limb; N] {
        let inverted = words.map(|word| Limb::new(!word.to_word()));
        let mut one = [Limb::new(0); N];
        if N != 0 {
            one[0] = Limb::new(1);
        }
        Self::add_words(&inverted, &one).0
    }

    pub(super) fn is_negative_words(words: &[Limb; N]) -> bool {
        words
            .last()
            .is_some_and(|word| word.to_word() >> (Word::BITS - 1) != 0)
    }

    pub(super) fn abs_words(words: &[Limb; N]) -> [Limb; N] {
        if Self::is_negative_words(words) {
            Self::wrapping_neg_words(words)
        } else {
            *words
        }
    }

    pub(super) fn gcd_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> [Limb; N] {
        let mut left = *lhs;
        let mut right = *rhs;
        while !Self::is_zero_words(&right) {
            let remainder = Self::div_rem_words(&left, &right).1;
            left = right;
            right = remainder;
        }
        left
    }

    pub(super) fn bit_len_words(words: &[Limb; N]) -> usize {
        words
            .iter()
            .rposition(|word| word.to_word() != 0)
            .map_or(0, |index| {
                index * Word::BITS as usize
                    + (Word::BITS - words[index].to_word().leading_zeros()) as usize
            })
    }

    pub(super) fn test_bit_words(words: &[Limb; N], index: usize) -> bool {
        words[index / Word::BITS as usize].to_word() >> (index % Word::BITS as usize) & 1 != 0
    }

    pub(super) fn is_zero_words(words: &[Limb; N]) -> bool {
        words.iter().all(|word| word.to_word() == 0)
    }

    pub(super) fn is_one_words(words: &[Limb; N]) -> bool {
        words.first() == Some(&Limb::new(1)) && words.iter().skip(1).all(|word| word.to_word() == 0)
    }

    pub(super) fn shr_one_words(words: &mut [Limb; N]) {
        let mut carry = 0 as Word;
        for word in words.iter_mut().rev() {
            let next = word.to_word() << (Word::BITS - 1);
            *word = Limb::new((word.to_word() >> 1) | carry);
            carry = next;
        }
    }
    pub(super) fn shl_one_words(words: &mut [Limb; N]) -> bool {
        let mut carry = 0 as Word;
        for word in words {
            let next = word.to_word() >> (Word::BITS - 1);
            *word = Limb::new((word.to_word() << 1) | carry);
            carry = next;
        }
        carry != 0
    }
}
