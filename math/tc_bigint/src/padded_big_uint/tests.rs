use alloc::vec;
use alloc::vec::Vec;

use crate::{
    BigUint, Choice, ConditionallySelectable, ConstantTimeEq, ConversionError, Limb, NonZero, Odd,
    PaddedBigUint, Word, ZeroizeOnDrop,
};

/// 由一個小數值建立寬度為 `limbs` 的值。
fn small(value: u8, limbs: usize) -> PaddedBigUint {
    PaddedBigUint::from_be_bytes(&[value], limbs).unwrap()
}

/// 由低位在前的字建立值，寬度即輸入長度。
fn from_words(words: &[Word]) -> PaddedBigUint {
    PaddedBigUint::from_limbs(words.iter().copied().map(Limb::new).collect())
}

/// 固定種子的 xorshift，讓隨機測試可以重現。
struct XorShift(u64);

impl XorShift {
    fn next_word(&mut self) -> Word {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as Word
    }

    fn next_value(&mut self, limbs: usize) -> PaddedBigUint {
        let words = (0..limbs).map(|_| self.next_word()).collect::<Vec<_>>();
        from_words(&words)
    }
}

#[cfg(feature = "rand_core")]
impl rand_core::TryRng for XorShift {
    type Error = rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

#[test]
fn every_arithmetic_method_keeps_the_constructed_width() {
    let value = small(9, 4);
    let other = small(5, 4);

    assert_eq!(value.add(&other).0.len(), 4);
    assert_eq!(value.sub(&other).0.len(), 4);
    let (low, high) = value.mul_wide(&other);
    assert_eq!(low.len(), 4);
    assert_eq!(high.len(), 4);
    assert_eq!(value.shl(70).0.len(), 4);
    assert_eq!(value.shr(70).len(), 4);
    assert_eq!(
        PaddedBigUint::conditional_select(&value, &other, Choice::from_lsb(1)).len(),
        4
    );
    assert_eq!(value.clone().len(), 4);
    assert_eq!(value.resize(9).unwrap().len(), 9);
}

#[test]
fn leading_zeros_are_kept_while_the_significant_width_shrinks() {
    let value = small(1, 4);

    assert_eq!(value.len(), 4);
    assert_eq!(value.significant_len(), 1);
    assert_eq!(value.bit_len(), 1);
    assert_eq!(value.byte_length_unsigned(), 1);

    let zero = PaddedBigUint::zero_with_limbs(4);
    assert_eq!(zero.len(), 4);
    assert_eq!(zero.significant_len(), 0);
    assert_eq!(zero.bit_len(), 0);
    // 無號零的最短編碼仍是一個位元組，與既有型別一致。
    assert_eq!(zero.byte_length_unsigned(), 1);
    assert!(zero.is_zero());
    assert_eq!(zero.ct_is_zero().unwrap_u8(), 1);
    assert_eq!(value.ct_is_zero().unwrap_u8(), 0);
}

#[test]
fn values_of_different_widths_compare_by_number() {
    assert_eq!(small(7, 1), small(7, 6));
    assert!(small(8, 1) > small(7, 6));
    assert!(from_words(&[0, 1]) > from_words(&[Word::MAX]));
    assert_eq!(
        PaddedBigUint::zero_with_limbs(0),
        PaddedBigUint::zero_with_limbs(5)
    );
}

#[test]
fn conversions_reject_values_that_do_not_fit() {
    let word_bytes = size_of::<Word>();

    assert_eq!(
        PaddedBigUint::from_be_bytes(&vec![1; word_bytes + 1], 1),
        Err(ConversionError::InputTooLarge)
    );
    // 超出的位元組全為零時不算溢位。
    let padded = vec![0; word_bytes + 1];
    assert!(PaddedBigUint::from_be_bytes(&padded, 1).is_ok());

    assert_eq!(
        PaddedBigUint::from_le_bytes(&vec![1; word_bytes + 1], 1),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        from_words(&[0, 1]).resize(1),
        Err(ConversionError::InputTooLarge)
    );
    assert!(from_words(&[1, 0]).resize(1).is_ok());
    assert_eq!(
        PaddedBigUint::from_big_uint(&BigUint::from(u32::MAX), 0),
        Err(ConversionError::InputTooLarge)
    );
}

#[test]
fn big_endian_bytes_round_trip_through_the_padded_width() {
    let value = from_words(&[0x0102_0304, 0]);
    let mut out = vec![0_u8; 2 * size_of::<Word>()];

    value.write_be_bytes(&mut out).unwrap();
    assert_eq!(PaddedBigUint::from_be_bytes(&out, 2).unwrap(), value);
    // 高位補零，最低的四個位元組帶著數值。
    assert_eq!(out[out.len() - 4..], [0x01, 0x02, 0x03, 0x04]);

    // 放不下時回報，且輸出保持原狀。
    let mut narrow = [0xAA_u8; 3];
    assert_eq!(
        value.write_be_bytes(&mut narrow),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(narrow, [0xAA; 3]);

    // 零也需要一個位元組，空輸出一律失敗。
    assert_eq!(
        PaddedBigUint::zero_with_limbs(1).write_be_bytes(&mut []),
        Err(ConversionError::BufferTooSmall)
    );
}

#[test]
fn carry_and_borrow_report_the_width_boundary() {
    let max = from_words(&[Word::MAX, Word::MAX]);
    let one = small(1, 2);

    let (sum, carry) = max.add(&one);
    assert!(carry);
    assert!(sum.is_zero());
    assert_eq!(sum.len(), 2);

    let (difference, borrow) = PaddedBigUint::zero_with_limbs(2).sub(&one);
    assert!(borrow);
    assert_eq!(difference, max);

    // 進位要跨過中間的滿位 limb。
    let (sum, carry) = from_words(&[Word::MAX, 0]).add(&one);
    assert!(!carry);
    assert_eq!(sum, from_words(&[0, 1]));
}

#[test]
fn in_place_arithmetic_matches_the_allocating_form() {
    let mut rng = XorShift(0x6c31_af08_25de_9147);

    for _ in 0..200 {
        let lhs = rng.next_value(3);
        let rhs = rng.next_value(3);

        let mut sum = lhs.clone();
        assert_eq!(sum.add_assign(&rhs), lhs.add(&rhs).1);
        assert_eq!(sum, lhs.add(&rhs).0);

        let mut difference = lhs.clone();
        assert_eq!(difference.sub_assign(&rhs), lhs.sub(&rhs).1);
        assert_eq!(difference, lhs.sub(&rhs).0);

        // 條件版本在 choice 為零時不得改動任何一個 limb。
        let mut untouched = lhs.clone();
        untouched.conditional_add_assign(&rhs, Choice::from_lsb(0));
        assert_eq!(untouched, lhs);
        untouched.conditional_assign(&rhs, Choice::from_lsb(0));
        assert_eq!(untouched, lhs);
        untouched.conditional_assign(&rhs, Choice::from_lsb(1));
        assert_eq!(untouched, rhs);
    }
}

#[test]
fn the_conditional_subtraction_only_fires_when_it_fits() {
    let modulus = from_words(&[101, 0]);

    // 大於等於模數時要減。
    let mut value = from_words(&[150, 0]);
    value.conditional_sub_assign(&modulus, Choice::from_lsb(0));
    assert_eq!(value, from_words(&[49, 0]));

    // 小於模數時保持原值。
    let mut value = from_words(&[49, 0]);
    value.conditional_sub_assign(&modulus, Choice::from_lsb(0));
    assert_eq!(value, from_words(&[49, 0]));

    // force 為一時無條件減，即使會借位。
    let mut value = from_words(&[49, 0]);
    value.conditional_sub_assign(&modulus, Choice::from_lsb(1));
    assert_eq!(value, from_words(&[49, 0]).sub(&modulus).0);
}

#[test]
fn wide_multiplication_matches_the_variable_length_type() {
    let mut rng = XorShift(0x2f6e_2b1c_9a45_31d7);

    for case in 0..200 {
        let width = case % 4 + 1;
        let lhs = rng.next_value(width);
        let rhs = rng.next_value(width);

        let (low, high) = lhs.mul_wide(&rhs);
        let product = PaddedBigUint::concat(&low, &high);

        assert_eq!(
            product.to_big_uint(),
            lhs.to_big_uint() * rhs.to_big_uint(),
            "case {case}"
        );
    }
}

#[test]
fn concat_and_split_at_are_inverse() {
    let low = from_words(&[1, 2]);
    let high = from_words(&[3]);
    let joined = PaddedBigUint::concat(&low, &high);

    assert_eq!(joined.len(), 3);
    let (split_low, split_high) = joined.split_at(2);
    assert_eq!(split_low, low);
    assert_eq!(split_high, high);
    assert_eq!(split_low.len(), 2);
    assert_eq!(split_high.len(), 1);

    // 切點超過寬度時高位段為零寬。
    let (all, empty) = joined.split_at(99);
    assert_eq!(all.len(), 3);
    assert!(empty.is_empty());
}

#[test]
fn shifts_are_bounded_by_the_padded_width() {
    let value = from_words(&[1, 0]);
    let bits = Word::BITS as usize;

    // 跨越 limb 邊界。
    let (shifted, lost) = value.shl(bits);
    assert!(!lost);
    assert_eq!(shifted, from_words(&[0, 1]));
    assert_eq!(shifted.shr(bits), value);

    // 移出頂端。
    let (shifted, lost) = from_words(&[0, 1]).shl(bits);
    assert!(lost);
    assert!(shifted.is_zero());

    // 只有高位的幾個位元移出。
    let (_, lost) = from_words(&[0, 1 << (bits - 1)]).shl(1);
    assert!(lost);
    let (_, lost) = from_words(&[0, 1]).shl(1);
    assert!(!lost);

    // 極端位移量不得 panic。
    let (shifted, lost) = value.shl(usize::MAX);
    assert!(shifted.is_zero());
    assert!(lost);
    assert!(value.shr(usize::MAX).is_zero());
    assert_eq!(value.shl(0).0, value);
    assert_eq!(value.shr(0), value);
}

#[test]
fn constant_time_equality_agrees_with_numeric_equality() {
    let mut rng = XorShift(0x51a4_7c33_0d19_86bb);

    for _ in 0..100 {
        let lhs = rng.next_value(3);
        let rhs = rng.next_value(3);
        assert_eq!(lhs.ct_eq(&rhs).unwrap_u8() == 1, lhs == rhs);
        assert_eq!(lhs.ct_eq(&lhs).unwrap_u8(), 1);
    }

    let one = small(1, 2);
    let zero = PaddedBigUint::zero_with_limbs(2);
    assert_eq!(
        PaddedBigUint::conditional_select(&zero, &one, Choice::from_lsb(1)),
        one
    );
    assert_eq!(
        PaddedBigUint::conditional_select(&zero, &one, Choice::from_lsb(0)),
        zero
    );
}

#[test]
#[should_panic(expected = "padded operands must have the same width")]
fn constant_time_equality_panics_on_mismatched_widths() {
    let _ = small(1, 2).ct_eq(&small(1, 3));
}

#[test]
#[should_panic(expected = "padded operands must have the same width")]
fn addition_panics_on_mismatched_widths() {
    let _ = small(1, 2).add(&small(1, 3));
}

#[test]
fn the_odd_and_non_zero_wrappers_accept_padded_values() {
    assert!(Odd::new(small(7, 4)).is_some());
    assert!(Odd::new(small(8, 4)).is_none());
    assert!(Odd::new(PaddedBigUint::zero_with_limbs(4)).is_none());
    // 包裝不改變寬度。
    assert_eq!(Odd::new(small(7, 4)).unwrap().into_inner().len(), 4);

    assert!(NonZero::new_padded(small(1, 4)).is_some());
    assert!(NonZero::new_padded(PaddedBigUint::zero_with_limbs(4)).is_none());
    assert_eq!(
        NonZero::new_padded(small(1, 4))
            .unwrap()
            .into_padded()
            .len(),
        4
    );
}

#[cfg(feature = "rand_core")]
#[test]
fn random_values_stay_below_the_public_upper_bound() {
    let mut rng = XorShift(0x77c1_de40_9b32_5a18);
    let upper = NonZero::new_padded(from_words(&[101, 0, 0])).unwrap();

    for _ in 0..200 {
        let value = PaddedBigUint::random_mod_vartime(&mut rng, &upper);
        // 結果寬度等於上界的寬度，不隨數值縮小。
        assert_eq!(value.len(), 3);
        assert!(value < *upper.as_ref());
    }
}

#[test]
fn bit_reads_agree_across_both_accessors() {
    let value = from_words(&[0b1011, 0b10]);
    let bits = Word::BITS as usize;

    for index in 0..(3 * bits) {
        assert_eq!(
            value.bit_choice(index).unwrap_u8() == 1,
            value.test_bit(index),
            "bit {index}"
        );
    }
    assert!(value.test_bit(0));
    assert!(!value.test_bit(2));
    assert!(value.test_bit(bits + 1));
    // 超出寬度一律讀到零。
    assert!(!value.test_bit(2 * bits));
    assert_eq!(value.bit_choice(2 * bits).unwrap_u8(), 0);
}

#[test]
fn erasure_policy_is_carried_by_the_type() {
    fn has_drop_policy<T: ZeroizeOnDrop>(_: &T) {}
    has_drop_policy(&small(1, 4));
}

#[test]
fn debug_output_reveals_the_width_but_not_the_value() {
    use alloc::format;

    let rendered = format!("{:?}", from_words(&[0xDEAD_BEEF, 0]));
    assert!(rendered.contains("2"), "{rendered}");
    assert!(!rendered.to_lowercase().contains("dead"), "{rendered}");
}

/// 常數時間方法的實作不得呼叫任何變動時間的輔助方法。
///
/// 這是粗糙的靜態回歸檢查，擋的是日後不小心引入的洩漏，不是正式證明。
#[test]
fn constant_time_methods_do_not_call_variable_time_helpers() {
    const CONSTANT_TIME_SOURCES: [(&str, &str); 4] = [
        ("add.rs", include_str!("add.rs")),
        ("sub.rs", include_str!("sub.rs")),
        ("mul.rs", include_str!("mul.rs")),
        ("shift.rs", include_str!("shift.rs")),
    ];

    for (name, source) in CONSTANT_TIME_SOURCES {
        let body = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for forbidden in ["significant_len(", "bit_len(", "is_zero("] {
            assert!(
                !body.contains(forbidden),
                "{name} 的常數時間路徑呼叫了變動時間的 {forbidden}"
            );
        }
    }
}

/// 本型別的任何路徑都不得砍掉前導零。
#[test]
fn no_path_normalizes_away_leading_zeros() {
    const SOURCES: [(&str, &str); 6] = [
        ("padded_big_uint.rs", include_str!("../padded_big_uint.rs")),
        ("add.rs", include_str!("add.rs")),
        ("sub.rs", include_str!("sub.rs")),
        ("mul.rs", include_str!("mul.rs")),
        ("shift.rs", include_str!("shift.rs")),
        ("random.rs", include_str!("random.rs")),
    ];

    for (name, source) in SOURCES {
        assert!(
            !source.contains("normalize"),
            "{name} 用到了會砍掉前導零的 normalize"
        );
    }
}
