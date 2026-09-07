use crate::{Choice, ConditionallySelectable, ConstantTimeEq, Limb, WideWord, Word};
use core::cmp::Ordering;

/// Exactly `N` little-endian limbs, stored in a private field without heap allocation.
///
/// `N = 0` represents a zero-width zero; addition, subtraction, and multiplication return zero without overflow.
/// All limbs are unsigned storage, and the highest bit is not a sign bit; signed interpretation belongs to higher layers.
/// Ordinary comparisons, division, GCD, and other arithmetic are not guaranteed to run in constant time.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LimbArray<const N: usize>([Limb; N]);

impl<const N: usize> LimbArray<N> {
    /// Creates a value from exactly `N` little-endian limbs, preserving leading zeros.
    pub const fn new(limbs: [Limb; N]) -> Self {
        Self(limbs)
    }

    /// Creates a value with all limbs set to zero.
    pub const fn zero() -> Self {
        Self([Limb::new(0); N])
    }

    /// Borrows all little-endian limbs, preserving the fixed length.
    pub const fn as_limbs(&self) -> &[Limb; N] {
        &self.0
    }

    /// Returns all little-endian limbs by value.
    pub const fn into_limbs(self) -> [Limb; N] {
        self.0
    }

    /// Returns the fixed-width sum and the carry flag from the highest limb.
    pub fn add(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = {
            let lhs = &self.0;
            let rhs = &rhs.0;
            let mut result = [Limb::new(0); N];
            let mut carry = Limb::new(0);
            for index in 0..N {
                (result[index], carry) = lhs[index].carrying_add(rhs[index], carry);
            }
            (result, carry.to_word() != 0)
        };
        (Self(value), overflow)
    }

    /// Returns the fixed-width difference and the final borrow flag after propagating through all limbs.
    pub fn sub(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = {
            let lhs = &self.0;
            let rhs = &rhs.0;
            let mut result = [Limb::new(0); N];
            let mut borrow = Limb::new(0);
            for index in 0..N {
                (result[index], borrow) = lhs[index].borrowing_sub(rhs[index], borrow);
            }
            (result, borrow.to_word() != 0)
        };
        (Self(value), overflow)
    }

    /// Returns the low half of the product; the overflow flag is true when the high half is nonzero.
    pub fn mul(&self, rhs: &Self) -> (Self, bool) {
        let (value, overflow) = {
            let lhs = &self.0;
            let rhs = &rhs.0;
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
                    let (low, high) =
                        (*left).carrying_mul_add(*right, result[index], Limb::new(carry));
                    result[index] = low;
                    carry = high.to_word();
                }
                overflow |= carry != 0;
            }

            (result, overflow)
        };
        (Self(value), overflow)
    }

    /// Returns the full product as `(low, high)`, with `N` limbs in each half.
    ///
    /// The full value is `low + high * 2^(N * Word::BITS)`.
    pub fn mul_wide(&self, rhs: &Self) -> (Self, Self) {
        let (low, high) = {
            let lhs = &self.0;
            let rhs = &rhs.0;
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
                    let (output, next_carry) =
                        (*left).carrying_mul_add(*right, Limb::new(current), Limb::new(carry));
                    if index < N {
                        low[index] = output;
                    } else {
                        high[index - N] = output;
                    }
                    carry = next_carry.to_word();
                }
                if N != 0 {
                    high[left_index] = Limb::new(carry);
                }
            }

            (low, high)
        };
        (Self(low), Self(high))
    }

    /// Returns the low and high halves of the full square.
    pub fn square_wide(&self) -> (Self, Self) {
        let (low, high) = {
            let value = &self.0;
            Self::mul_wide_words(value, value)
        };
        (Self(low), Self(high))
    }

    /// Adds the full product to a double-width accumulator, returning an overflow flag beyond `2N` limbs.
    ///
    /// Updates `low` and `high` in place, retaining the result modulo `2^(2N * Word::BITS)` on overflow.
    // 只有測試消費：mul_add_to 與 shr_one 是既有回歸測試的入口。
    #[allow(dead_code)]
    pub fn mul_add_to(&self, rhs: &Self, low: &mut Self, high: &mut Self) -> bool {
        {
            let lhs = &self.0;
            let rhs = &rhs.0;
            let low = &mut low.0;
            let high = &mut high.0;
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
    }

    /// Performs unsigned division, returning the quotient and remainder; control flow depends on the values.
    ///
    /// # Panics
    /// Panics if the divisor is zero, including when `N = 0`.
    pub fn div_rem(&self, rhs: &Self) -> (Self, Self) {
        let (quotient, remainder) = Self::div_rem_words(&self.0, &rhs.0);
        (Self(quotient), Self(remainder))
    }

    /// Computes the remainder of a double-width unsigned value, with `self` as the low half and `high` as the high half.
    ///
    /// # Panics
    /// Panics if `modulus` is zero, including when `N = 0`. This method is not guaranteed to run in constant time.
    pub fn wide_rem(&self, high: &Self, modulus: &Self) -> Self {
        Self(Self::wide_rem_words(&self.0, &high.0, &modulus.0))
    }

    /// Returns the additive inverse modulo `2^(N * Word::BITS)`; a zero-width value remains zero.
    pub fn wrapping_neg(&self) -> Self {
        Self({
            let words = &self.0;
            let inverted = words.map(|word| Limb::new(!word.to_word()));
            let mut one = [Limb::new(0); N];
            if N != 0 {
                one[0] = Limb::new(1);
            }
            Self::add_words(&inverted, &one).0
        })
    }

    /// Computes the unsigned greatest common divisor, with `gcd(0, 0) = 0`; control flow depends on the values.
    pub fn gcd(&self, rhs: &Self) -> Self {
        Self({
            let lhs = &self.0;
            let rhs = &rhs.0;
            let mut left = *lhs;
            let mut right = *rhs;
            while !Self::is_zero_words(&right) {
                let remainder = Self::div_rem_words(&left, &right).1;
                left = right;
                right = remainder;
            }
            left
        })
    }

    /// Returns the number of significant bits in the unsigned representation, or zero for zero.
    pub fn bit_len(&self) -> usize {
        {
            let words = &self.0;
            words
                .iter()
                .rposition(|word| word.to_word() != 0)
                .map_or(0, |index| {
                    index * Word::BITS as usize
                        + (Word::BITS - words[index].to_word().leading_zeros()) as usize
                })
        }
    }

    /// Returns the bitwise AND of every limb pair.
    pub fn bitand(&self, rhs: &Self) -> Self {
        Self(core::array::from_fn(|index| {
            Limb::new(self.0[index].to_word() & rhs.0[index].to_word())
        }))
    }

    /// Returns the bitwise OR of every limb pair.
    pub fn bitor(&self, rhs: &Self) -> Self {
        Self(core::array::from_fn(|index| {
            Limb::new(self.0[index].to_word() | rhs.0[index].to_word())
        }))
    }

    /// Returns the bitwise exclusive OR of every limb pair.
    pub fn bitxor(&self, rhs: &Self) -> Self {
        Self(core::array::from_fn(|index| {
            Limb::new(self.0[index].to_word() ^ rhs.0[index].to_word())
        }))
    }

    /// Returns the bitwise complement of every limb, keeping the fixed width.
    pub fn not(&self) -> Self {
        Self(core::array::from_fn(|index| {
            Limb::new(!self.0[index].to_word())
        }))
    }

    /// Tests the bit at `index`, with index zero denoting the least significant bit.
    ///
    /// # Panics
    /// Panics if the index is outside the fixed width; zero-width values have no valid indices.
    pub fn test_bit(&self, index: usize) -> bool {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        {
            let words = &self.0;
            words[index / Word::BITS as usize].to_word() >> (index % Word::BITS as usize) & 1 != 0
        }
    }

    /// Returns a new value with the bit at `index` set, with index zero denoting the least significant bit.
    ///
    /// # Panics
    /// Panics if the index is outside the fixed width; zero-width values have no valid indices.
    pub fn set_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        Self({
            let words = &self.0;
            let mut result = *words;
            let word = index / Word::BITS as usize;
            result[word] =
                Limb::new(result[word].to_word() | ((1 as Word) << (index % Word::BITS as usize)));
            result
        })
    }

    /// Returns a new value with the bit at `index` cleared, with index zero denoting the least significant bit.
    ///
    /// # Panics
    /// Panics if the index is outside the fixed width; zero-width values have no valid indices.
    pub fn clear_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        Self({
            let words = &self.0;
            let mut result = *words;
            let word = index / Word::BITS as usize;
            result[word] =
                Limb::new(result[word].to_word() & !((1 as Word) << (index % Word::BITS as usize)));
            result
        })
    }

    /// Returns a new value with the bit at `index` flipped, with index zero denoting the least significant bit.
    ///
    /// # Panics
    /// Panics if the index is outside the fixed width; zero-width values have no valid indices.
    pub fn flip_bit(&self, index: usize) -> Self {
        assert!(
            index < N * Word::BITS as usize,
            "bit index is outside fixed width"
        );
        Self({
            let words = &self.0;
            let mut result = *words;
            let word = index / Word::BITS as usize;
            result[word] =
                Limb::new(result[word].to_word() ^ ((1 as Word) << (index % Word::BITS as usize)));
            result
        })
    }

    /// Returns whether all limbs are zero; true for zero width. This comparison may exit early.
    pub fn is_zero(&self) -> bool {
        {
            let words = &self.0;
            words.iter().all(|word| word.to_word() == 0)
        }
    }

    /// Returns whether the value equals one; false for zero width. This comparison may exit early.
    pub fn is_one(&self) -> bool {
        {
            let words = &self.0;
            words.first() == Some(&Limb::new(1))
                && words.iter().skip(1).all(|word| word.to_word() == 0)
        }
    }

    /// Shifts right logically by one bit in place, discarding the lowest bit; zero width is unchanged.
    // 只有測試消費：mul_add_to 與 shr_one 是既有回歸測試的入口。
    #[allow(dead_code)]
    pub fn shr_one(&mut self) {
        {
            let words = &mut self.0;
            let mut carry = 0 as Word;
            for word in words.iter_mut().rev() {
                let next = word.to_word() << (Word::BITS - 1);
                *word = Limb::new((word.to_word() >> 1) | carry);
                carry = next;
            }
        };
    }

    /// Shifts left by one bit in place and returns the highest bit shifted out; false for zero width.
    // 只有測試消費：與 shr_one 成對，是既有回歸測試的入口。
    #[allow(dead_code)]
    pub fn shl_one(&mut self) -> bool {
        Self::shl_one_words(&mut self.0)
    }

    fn cmp_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> Ordering {
        lhs.iter().rev().cmp(rhs.iter().rev())
    }

    fn add_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], bool) {
        let mut result = [Limb::new(0); N];
        let mut carry = Limb::new(0);
        for index in 0..N {
            (result[index], carry) = lhs[index].carrying_add(rhs[index], carry);
        }
        (result, carry.to_word() != 0)
    }

    #[inline]
    fn mul_wide_words(lhs: &[Limb; N], rhs: &[Limb; N]) -> ([Limb; N], [Limb; N]) {
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
                let (output, next_carry) =
                    (*left).carrying_mul_add(*right, Limb::new(current), Limb::new(carry));
                if index < N {
                    low[index] = output;
                } else {
                    high[index - N] = output;
                }
                carry = next_carry.to_word();
            }
            if N != 0 {
                high[left_index] = Limb::new(carry);
            }
        }

        (low, high)
    }
    fn div_rem_words(dividend: &[Limb; N], divisor: &[Limb; N]) -> ([Limb; N], [Limb; N]) {
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
    fn wide_rem_words(low: &[Limb; N], high: &[Limb; N], modulus: &[Limb; N]) -> [Limb; N] {
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
        // Process the normalized double-width dividend word by word, keeping only the current remainder window to avoid a 2N array.
        let input_len = N + high_len;
        let mut remainder = [Limb::new(0); N];
        let base = (1 as WideWord) << Word::BITS;
        let modulus_high = normalized_modulus[modulus_len - 1].to_word() as WideWord;
        let modulus_next = normalized_modulus[modulus_len - 2].to_word() as WideWord;
        // The highest modulus_len words form a prefix smaller than the modulus, initializing the rolling remainder.
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

    fn set_word_at(words: &mut [Limb; N], extra: &mut Word, index: usize, value: Word) {
        if index < N {
            words[index] = Limb::new(value);
        } else {
            debug_assert_eq!(index, N);
            *extra = value;
        }
    }

    fn is_zero_words(words: &[Limb; N]) -> bool {
        words.iter().all(|word| word.to_word() == 0)
    }

    fn shl_one_words(words: &mut [Limb; N]) -> bool {
        let mut carry = 0 as Word;
        for word in words {
            let next = word.to_word() >> (Word::BITS - 1);
            *word = Limb::new((word.to_word() << 1) | carry);
            carry = next;
        }
        carry != 0
    }
}

impl<const N: usize> Default for LimbArray<N> {
    fn default() -> Self {
        Self::zero()
    }
}

/// Compares unsigned values starting at the highest limb, with possible early exit.
impl<const N: usize> Ord for LimbArray<N> {
    fn cmp(&self, rhs: &Self) -> Ordering {
        {
            let lhs = &self.0;
            let rhs = &rhs.0;
            lhs.iter().rev().cmp(rhs.iter().rev())
        }
    }
}
impl<const N: usize> PartialOrd for LimbArray<N> {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

/// Selects limb by limb without branching on input values; zero selects `a`, and one selects `b`.
impl<const N: usize> ConditionallySelectable for LimbArray<N> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(<[Limb; N]>::conditional_select(&a.0, &b.0, choice))
    }
}

/// Compares all `N` limbs without early exit; two zero-width values are equal.
impl<const N: usize> ConstantTimeEq for LimbArray<N> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.0.ct_eq(&rhs.0)
    }
}

#[cfg(test)]
mod doc_tests {
    use super::*;
    use crate::{Choice, ConditionallySelectable, ConstantTimeEq};

    #[test]
    fn limb_array_example() {
        let value = LimbArray::new([Limb::new(7), Limb::new(0)]);
        assert_eq!(value.as_limbs()[0].to_word(), 7);
        assert_eq!(LimbArray::<0>::zero().bit_len(), 0);
    }

    #[test]
    fn fn_example() {
        assert_eq!(LimbArray::new([Limb::new(3)]).as_limbs(), &[Limb::new(3)]);
    }

    #[test]
    fn fn_2_example() {
        assert!(LimbArray::<4>::zero().is_zero());
    }

    #[test]
    fn fn_3_example() {
        assert_eq!(LimbArray::<3>::zero().as_limbs().len(), 3);
    }

    #[test]
    fn fn_4_example() {
        assert_eq!(LimbArray::<2>::zero().into_limbs(), [Limb::new(0); 2]);
    }

    #[test]
    fn add_example() {
        let max = LimbArray::new([Limb::new(Word::MAX)]);
        assert_eq!(
            max.add(&LimbArray::new([Limb::new(1)])),
            (LimbArray::zero(), true)
        );
    }

    #[test]
    fn sub_example() {
        let one = LimbArray::new([Limb::new(1)]);
        assert_eq!(
            LimbArray::zero().sub(&one),
            (LimbArray::new([Limb::new(Word::MAX)]), true)
        );
    }

    #[test]
    fn mul_example() {
        let max = LimbArray::new([Limb::new(Word::MAX)]);
        assert_eq!(max.mul(&max), (LimbArray::new([Limb::new(1)]), true));
    }

    #[test]
    fn mul_wide_example() {
        let max = LimbArray::new([Limb::new(Word::MAX)]);
        assert_eq!(
            max.mul_wide(&max),
            (
                LimbArray::new([Limb::new(1)]),
                LimbArray::new([Limb::new(Word::MAX - 1)])
            )
        );
    }

    #[test]
    fn square_wide_example() {
        let x = LimbArray::new([Limb::new(7)]);
        assert_eq!(
            x.square_wide(),
            (LimbArray::new([Limb::new(49)]), LimbArray::zero())
        );
    }

    #[test]
    fn mul_add_to_example() {
        let x = LimbArray::new([Limb::new(3)]);
        let mut low = LimbArray::new([Limb::new(1)]);
        let mut high = LimbArray::zero();
        assert!(!x.mul_add_to(&x, &mut low, &mut high));
        assert_eq!(low.as_limbs()[0].to_word(), 10);
    }

    #[test]
    fn div_rem_example() {
        let a = LimbArray::new([Limb::new(17)]);
        let b = LimbArray::new([Limb::new(5)]);
        assert_eq!(
            a.div_rem(&b),
            (
                LimbArray::new([Limb::new(3)]),
                LimbArray::new([Limb::new(2)])
            )
        );
    }

    #[test]
    fn wide_rem_example() {
        let low = LimbArray::new([Limb::new(Word::MAX)]);
        let high = LimbArray::new([Limb::new(1)]);
        let modulus = LimbArray::new([Limb::new(2)]);
        assert_eq!(
            low.wide_rem(&high, &modulus),
            LimbArray::new([Limb::new(1)])
        );
    }

    #[test]
    fn wrapping_neg_example() {
        assert_eq!(
            LimbArray::new([Limb::new(1)]).wrapping_neg(),
            LimbArray::new([Limb::new(Word::MAX)])
        );
    }

    #[test]
    fn gcd_example() {
        assert_eq!(
            LimbArray::new([Limb::new(12)]).gcd(&LimbArray::new([Limb::new(8)])),
            LimbArray::new([Limb::new(4)])
        );
    }

    #[test]
    fn bit_len_example() {
        assert_eq!(LimbArray::new([Limb::new(8)]).bit_len(), 4);
    }

    #[test]
    fn test_bit_example() {
        let x = LimbArray::new([Limb::new(8)]);
        assert!(x.test_bit(3));
        assert!(!x.test_bit(0));
    }

    #[test]
    fn set_bit_example() {
        let value = LimbArray::<2>::zero().set_bit(Word::BITS as usize);
        assert!(value.test_bit(Word::BITS as usize));
    }

    #[test]
    fn clear_bit_example() {
        let value = LimbArray::new([Limb::new(1)]).clear_bit(0);
        assert!(!value.test_bit(0));
    }

    #[test]
    fn flip_bit_example() {
        let value = LimbArray::<1>::zero().flip_bit(0);
        assert!(value.test_bit(0));
        assert_eq!(value.flip_bit(0), LimbArray::zero());
    }

    #[test]
    fn is_zero_example() {
        assert!(LimbArray::<0>::zero().is_zero());
    }

    #[test]
    fn is_one_example() {
        assert!(LimbArray::new([Limb::new(1), Limb::new(0)]).is_one());
    }

    #[test]
    fn shr_one_example() {
        let mut x = LimbArray::new([Limb::new(7)]);
        x.shr_one();
        assert_eq!(x.as_limbs()[0].to_word(), 3);
    }

    #[test]
    fn shl_one_example() {
        let mut x = LimbArray::new([Limb::new(1 << (Word::BITS - 1))]);
        assert!(x.shl_one());
        assert!(x.is_zero());
    }

    #[test]
    fn const_n_example() {
        use core::cmp::Ordering;
        let a = LimbArray::new([Limb::new(9), Limb::new(0)]);
        let b = LimbArray::new([Limb::new(0), Limb::new(1)]);
        assert_eq!(a.cmp(&b), Ordering::Less);
    }

    #[test]
    fn const_n_two_example() {
        let a = LimbArray::<1>::zero();
        let b = LimbArray::new([Limb::new(7)]);
        assert_eq!(
            LimbArray::conditional_select(&a, &b, Choice::from_lsb(1)),
            b
        );
    }

    #[test]
    fn const_n_three_example() {
        assert_eq!(
            LimbArray::<0>::zero().ct_eq(&LimbArray::zero()).unwrap_u8(),
            1
        );
    }
}

/// Fuzzed comparison against num-bigint.
#[cfg(test)]
mod oracle_tests {
    use alloc::vec::Vec;

    use crate::{Choice, ConditionallySelectable, ConstantTimeEq, Limb, LimbArray, WideWord, Word};
    use num_bigint::BigUint;

    fn next(state: &mut u64) -> Word {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state as Word
    }

    fn oracle<const N: usize>(value: &LimbArray<N>) -> BigUint {
        let bytes: Vec<_> = value
            .as_limbs()
            .iter()
            .flat_map(|limb| limb.to_word().to_le_bytes())
            .collect();
        BigUint::from_bytes_le(&bytes)
    }

    fn assert_same<const N: usize>(value: LimbArray<N>, expected: BigUint) {
        let bytes = expected.to_bytes_le();
        assert!(expected.bits() <= (N * Word::BITS as usize) as u64);
        let expected_words: [Word; N] = core::array::from_fn(|index| {
            let mut word = 0 as Word;
            for byte in 0..core::mem::size_of::<Word>() {
                word |= (bytes
                    .get(index * core::mem::size_of::<Word>() + byte)
                    .copied()
                    .unwrap_or(0) as Word)
                    << (byte * 8);
            }
            word
        });
        assert_eq!(value.into_limbs().map(Limb::to_word), expected_words);
    }

    // Reconstruct both halves using the independent oracle's shifts and addition, not the arithmetic under test.
    fn joined<const N: usize>(low: &LimbArray<N>, high: &LimbArray<N>) -> BigUint {
        oracle(low) + (oracle(high) << (N * Word::BITS as usize))
    }

    fn random_cases<const N: usize>() {
        let mut state = 0x243f_6a88_85a3_08d3;
        let width = N * Word::BITS as usize;
        let radix = BigUint::from(1_u8) << width;
        let mask = &radix - 1_u8;
        let wide_radix = &radix * &radix;
        let wide_mask = &wide_radix - 1_u8;
        for case in 0..600 {
            let mut a: [Limb; N] = core::array::from_fn(|_| Limb::new(next(&mut state)));
            let mut b: [Limb; N] = core::array::from_fn(|_| Limb::new(next(&mut state)));
            // Cover single-word divisors, leading zeros, normalization boundaries, full carry chains, and equal operands.
            let len = case % N + 1;
            b[len..].fill(Limb::new(0));
            match case % 6 {
                0 => b[len - 1] = Limb::new(1),
                1 => b[len - 1] = Limb::new(Word::MAX),
                2 => a.fill(Limb::new(Word::MAX)),
                3 => a = b,
                4 => a.fill(Limb::new(0)),
                _ => {}
            }
            if b.iter().all(|word| word.to_word() == 0) {
                b[0] = Limb::new(1);
            }
            let a = LimbArray::new(a);
            let b = LimbArray::new(b);
            let oa = oracle(&a);
            let ob = oracle(&b);
            assert_eq!(a.cmp(&b), oa.cmp(&ob));
            let sum = &oa + &ob;
            let product = &oa * &ob;
            for ((value, flag), expected, expected_flag) in [
                (a.add(&b), &sum & &mask, sum >= radix),
                (a.sub(&b), (&oa + &radix - &ob) & &mask, oa < ob),
                (a.mul(&b), &product & &mask, product >= radix),
            ] {
                assert_same(value, expected);
                assert_eq!(flag, expected_flag);
            }
            let (low, high) = a.mul_wide(&b);
            assert_same(low, &product & &mask);
            assert_same(high, &product >> width);
            assert_eq!(joined(&low, &high), product);
            let square = &oa * &oa;
            let (low, high) = a.square_wide();
            assert_same(low, &square & &mask);
            assert_same(high, &square >> width);
            let (q, r) = a.div_rem(&b);
            assert_same(q, &oa / &ob);
            assert_same(r, &oa % &ob);
            let (mut left, mut right) = (oa.clone(), ob.clone());
            while right != BigUint::from(0_u8) {
                let remainder = &left % &right;
                left = right;
                right = remainder;
            }
            assert_same(a.gcd(&b), left);
            let negated = (&radix - &oa) & &mask;
            assert_same(a.wrapping_neg(), negated.clone());
            let negative = oa.bit((width - 1) as u64);
            assert_eq!(a.bit_len(), oa.bits() as usize);
            assert_eq!(a.is_zero(), oa == BigUint::from(0_u8));
            assert_eq!(a.is_one(), oa == BigUint::from(1_u8));
            for bit in 0..width {
                assert_eq!(a.test_bit(bit), oa.bit(bit as u64));
            }
            let mut shifted = a;
            assert_eq!(shifted.shl_one(), negative);
            assert_same(shifted, (&oa << 1_usize) & &mask);
            shifted = a;
            shifted.shr_one();
            assert_same(shifted, &oa >> 1_usize);
            let mut acc_low = LimbArray::new(core::array::from_fn(|_| Limb::new(next(&mut state))));
            let mut acc_high =
                LimbArray::new(core::array::from_fn(|_| Limb::new(next(&mut state))));
            assert_same(a.wide_rem(&acc_high, &b), joined(&a, &acc_high) % &ob);
            let expected = joined(&acc_low, &acc_high) + &product;
            let overflow = a.mul_add_to(&b, &mut acc_low, &mut acc_high);
            assert_same(acc_low, &expected & &mask);
            assert_same(acc_high, (&expected >> width) & &mask);
            assert_eq!(joined(&acc_low, &acc_high), &expected & &wide_mask);
            assert_eq!(overflow, expected >= wide_radix);
            assert_eq!(a.ct_eq(&b).unwrap_u8(), (oa == ob) as u8);
            assert_eq!(a.ct_eq(&a).unwrap_u8(), 1);
            for bit in [0, 1] {
                assert_eq!(
                    LimbArray::conditional_select(&a, &b, Choice::from_lsb(bit)),
                    if bit == 0 { a } else { b }
                );
            }
        }
    }

    #[test]
    fn every_array_operation_matches_num_bigint() {
        random_cases::<1>();
        random_cases::<2>();
        random_cases::<4>();
        random_cases::<8>();
    }

    #[test]
    fn empty_width_and_full_carry_borrow_chains() {
        let z = LimbArray::<0>::zero();
        assert_eq!(z, LimbArray::default());
        assert_eq!(z.as_limbs(), &[]);
        assert_eq!(z.add(&z), (z, false));
        assert_eq!(z.sub(&z), (z, false));
        assert_eq!(z.mul(&z), (z, false));
        assert_eq!(z.mul_wide(&z), (z, z));
        assert_eq!(z.square_wide(), (z, z));
        let (mut low, mut high) = (z, z);
        assert!(!z.mul_add_to(&z, &mut low, &mut high));
        assert!(!low.shl_one());
        low.shr_one();
        assert_eq!((low, high), (z, z));
        assert_eq!(z.gcd(&z), z);
        assert_eq!(z.wrapping_neg(), z);
        assert!(z.is_zero());
        assert!(!z.is_one());
        assert_eq!(z.bit_len(), 0);
        assert_eq!(z.cmp(&z), core::cmp::Ordering::Equal);
        assert_eq!(z.ct_eq(&z).unwrap_u8(), 1);
        assert_eq!(
            LimbArray::conditional_select(&z, &z, Choice::from_lsb(1)),
            z
        );
        let max = LimbArray::new([Limb::new(Word::MAX); 4]);
        let one = LimbArray::new([Limb::new(1), Limb::new(0), Limb::new(0), Limb::new(0)]);
        assert_eq!(max.add(&one), (LimbArray::zero(), true));
        assert_eq!(LimbArray::zero().sub(&one), (max, true));
        let mut low = max;
        let mut high = max;
        assert!(one.mul_add_to(&one, &mut low, &mut high));
        assert_eq!((low, high), (LimbArray::zero(), LimbArray::zero()));
        let min = LimbArray::new([Limb::new(0), Limb::new(1 << (Word::BITS - 1))]);
        assert_eq!(min.wrapping_neg(), min);
        for index in 0..4 {
            let mut limbs = max.into_limbs();
            limbs[index] = Limb::new(Word::MAX - 1);
            assert_eq!(max.ct_eq(&LimbArray::new(limbs)).unwrap_u8(), 0);
        }
    }

    #[test]
    fn bit_changes_cover_every_limb_boundary() {
        const N: usize = 3;
        let zero = LimbArray::<N>::zero();
        for index in [
            0,
            Word::BITS as usize - 1,
            Word::BITS as usize,
            N * Word::BITS as usize - 1,
        ] {
            let set = zero.set_bit(index);
            assert!(set.test_bit(index));
            assert!(!set.clear_bit(index).test_bit(index));
            assert_eq!(zero.flip_bit(index).flip_bit(index), zero);
        }
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn test_bit_rejects_out_of_range_index() {
        let _ = LimbArray::<2>::zero().test_bit(2 * Word::BITS as usize);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn set_bit_rejects_out_of_range_index() {
        let _ = LimbArray::<2>::zero().set_bit(2 * Word::BITS as usize);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn clear_bit_rejects_out_of_range_index() {
        let _ = LimbArray::<2>::zero().clear_bit(2 * Word::BITS as usize);
    }

    #[test]
    #[should_panic(expected = "bit index is outside fixed width")]
    fn flip_bit_rejects_out_of_range_index() {
        let _ = LimbArray::<2>::zero().flip_bit(2 * Word::BITS as usize);
    }

    #[test]
    fn invalid_inputs_panic() {
        let zero = Limb::new(0);
        assert!(std::panic::catch_unwind(|| zero.borrowing_sub(zero, Limb::new(2))).is_err());
        let z = LimbArray::<1>::zero();
        assert!(std::panic::catch_unwind(|| z.div_rem(&z)).is_err());
        assert!(std::panic::catch_unwind(|| z.wide_rem(&z, &z)).is_err());
        assert!(std::panic::catch_unwind(|| z.test_bit(Word::BITS as usize)).is_err());
        let z = LimbArray::<0>::zero();
        assert!(std::panic::catch_unwind(|| z.div_rem(&z)).is_err());
        assert!(std::panic::catch_unwind(|| z.wide_rem(&z, &z)).is_err());
        assert!(std::panic::catch_unwind(|| z.test_bit(0)).is_err());
    }
    #[test]
    fn limb_operations_match_native_and_double_width_words() {
        let mut state = 0x1319_8a2e_0370_7344;
        for _ in 0..4000 {
            let a = next(&mut state);
            let b = next(&mut state);
            let carry = next(&mut state);
            let x = Limb::new(a);
            let y = Limb::new(b);
            let sum = a as WideWord + b as WideWord + carry as WideWord;
            let (low, high) = x.carrying_add(y, Limb::new(carry));
            assert_eq!(
                (low.to_word(), high.to_word()),
                (sum as Word, (sum >> Word::BITS) as Word)
            );
            for borrow in [0, 1] {
                let (first, b1) = a.overflowing_sub(b);
                let (difference, b2) = first.overflowing_sub(borrow);
                assert_eq!(
                    x.borrowing_sub(y, Limb::new(borrow)),
                    (Limb::new(difference), Limb::new((b1 | b2) as Word))
                );
            }
            assert_eq!(x.overflowing_add(y), {
                let (v, f) = a.overflowing_add(b);
                (Limb::new(v), f)
            });
            assert_eq!(x.overflowing_sub(y), {
                let (v, f) = a.overflowing_sub(b);
                (Limb::new(v), f)
            });
            assert_eq!(x.wrapping_add(y).to_word(), a.wrapping_add(b));
            assert_eq!(x.wrapping_sub(y).to_word(), a.wrapping_sub(b));
            assert_eq!(x.wrapping_neg().to_word(), a.wrapping_neg());
            let product = a as WideWord * b as WideWord;
            assert_eq!(
                x.widening_mul(y),
                (
                    Limb::new(product as Word),
                    Limb::new((product >> Word::BITS) as Word)
                )
            );
            assert_eq!(Limb::new(x.to_word() & y.to_word()).to_word(), a & b);
            assert_eq!(Limb::new(x.to_word() | y.to_word()).to_word(), a | b);
            assert_eq!(Limb::new(x.to_word() ^ y.to_word()).to_word(), a ^ b);
            assert_eq!(Limb::new(!x.to_word()).to_word(), !a);
            let shift = carry as usize % Word::BITS as usize;
            assert_eq!(Limb::new(x.to_word() << shift).to_word(), a << shift);
            assert_eq!(Limb::new(x.to_word() >> shift).to_word(), a >> shift);
            let small_a = Limb::new(a & 0xff);
            let small_b = Limb::new(b & 0xff);
            assert_eq!(
                small_a.widening_mul(small_b).0.to_word(),
                (a & 0xff) * (b & 0xff)
            );
            assert_eq!(
                small_a.wrapping_add(small_b).to_word(),
                (a & 0xff) + (b & 0xff)
            );
            let mut assigned = small_a;
            assigned = assigned.wrapping_add(small_b);
            assigned = assigned.wrapping_sub(small_b);
            assert_eq!(assigned, small_a);
            assert_eq!(x.ct_eq(&y).unwrap_u8(), (a == b) as u8);
            assert_eq!(x.ct_eq(&x).unwrap_u8(), 1);
            for bit in [0, 1] {
                assert_eq!(
                    Limb::conditional_select(&x, &y, Choice::from_lsb(bit)),
                    if bit == 0 { x } else { y }
                );
            }
        }
    }
}
