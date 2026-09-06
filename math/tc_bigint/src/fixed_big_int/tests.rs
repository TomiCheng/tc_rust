//! Cross-module tests for the parent integer type.

use super::*;
use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{ParseBigIntError, Pow};

type I128 = FixedBigInt<{ 128 / Word::BITS as usize }>;

#[test]
fn fixed_signed_io_is_twos_complement_and_little_endian() {
    let value = I128::from(-2_i8);
    let mut bytes = [0_u8; 16];
    let mut words32 = [0_u32; 4];
    let mut words64 = [0_u64; 2];

    assert_eq!(value.write_le_bytes(&mut bytes), Ok(16));
    assert_eq!(
        bytes,
        [
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff
        ]
    );
    assert_eq!(value.write_le_u32(&mut words32), Ok(4));
    assert_eq!(words32, [0xffff_fffe, u32::MAX, u32::MAX, u32::MAX]);
    assert_eq!(value.write_le_u64(&mut words64), Ok(2));
    assert_eq!(words64, [u64::MAX - 1, u64::MAX]);
}

#[test]
fn right_shift_sign_extends() {
    assert_eq!((I128::from(-3_i8) >> 1).to_i64(), Some(-2));
    assert_eq!((I128::from(3_i8) >> 1).to_i64(), Some(1));
}

#[test]
fn euclidean_remainder_and_modular_power_match_known_values() {
    let three = I128::from(3_i8);
    let seven = I128::from(7_i8);

    assert_eq!(I128::from(-7_i8).rem_euclid(&three), I128::from(2_i8));
    assert_eq!(three.mod_pow(&I128::from(4_i8), &seven), I128::from(4_i8));
    assert_eq!(three.mod_pow(&I128::from(-1_i8), &seven), I128::from(5_i8));
}

#[test]
fn public_state_bit_and_parsing_methods_cover_signed_cases() {
    assert!(I128::default().is_zero());
    assert!(I128::min_value().is_negative());
    assert!(!I128::max_value().is_negative());
    assert_eq!(
        I128::zero().as_limbs(),
        &[Limb::new(0); 128 / Word::BITS as usize]
    );
    assert_eq!(I128::from(-7_i8).abs(), I128::from(7_i8));

    let value = I128::from(0b1010_i8);
    assert_eq!(value.bit_length(), 4);
    assert_eq!(value.bit_count(), 2);
    assert!(value.test_bit(3));
    assert!(!value.test_bit(128));
    assert!(I128::from(-1_i8).test_bit(128));
    assert_eq!(value.set_bit(0), I128::from(0b1011_i8));
    assert_eq!(value.clear_bit(3), I128::from(0b0010_i8));
    assert_eq!(value.flip_bit(1), I128::from(0b1000_i8));
    assert_eq!(value.lowest_set_bit(), Some(1));
    assert_eq!(I128::zero().lowest_set_bit(), None);
    assert_eq!(value.and_not(&I128::from(0b0011_i8)), I128::from(8_i8));

    assert_eq!(I128::from_str_radix("+7F", 16), Ok(I128::from(127_i8)));
    assert_eq!(I128::from_str_radix("-7F", 16), Ok(I128::from(-127_i8)));
    assert_eq!(
        I128::from_str_radix("", 10),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(
        FixedBigInt::<1>::from_str_radix("1".repeat(Word::BITS as usize).as_str(), 2),
        Err(ParseBigIntError::Overflow)
    );
}

#[test]
fn bounds_default_and_leading_zeros_are_available() {
    assert_eq!(I128::MIN, I128::min_value());
    assert_eq!(I128::MAX, I128::max_value());
    assert_eq!(I128::default(), I128::zero());
    assert_eq!(I128::zero().leading_zeros(), 128);
    assert_eq!(I128::from(1_i8).leading_zeros(), 127);
    assert_eq!(I128::from(-1_i8).leading_zeros(), 0);
}

#[test]
fn signed_unsigned_decoders_try_from_and_writer_errors_are_covered() {
    assert_eq!(I128::from_le_bytes(&[0xfe]), Ok(I128::from(-2_i8)));
    assert_eq!(I128::from_le_u32(&[u32::MAX - 1]), Ok(I128::from(-2_i8)));
    assert_eq!(I128::from_le_u64(&[u64::MAX - 1]), Ok(I128::from(-2_i8)));
    assert_eq!(
        I128::from_unsigned_le_bytes(&[0xfe]),
        Ok(I128::from(254_u16))
    );
    assert_eq!(
        I128::from_unsigned_le_u32(&[u32::MAX]),
        Ok(I128::from(u32::MAX))
    );
    assert_eq!(
        I128::from_unsigned_le_u64(&[u64::MAX]),
        Ok(I128::from(u64::MAX))
    );
    assert_eq!(I128::try_from(&[0xfe_u8][..]), Ok(I128::from(-2_i8)));
    assert_eq!(I128::try_from(&[u32::MAX - 1][..]), Ok(I128::from(-2_i8)));
    assert_eq!(I128::try_from(&[u64::MAX - 1][..]), Ok(I128::from(-2_i8)));

    assert_eq!(
        FixedBigInt::<0>::from_le_bytes(&[1]),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        FixedBigInt::<0>::from_unsigned_le_u32(&[1]),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        FixedBigInt::<0>::from_unsigned_le_u64(&[1]),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        I128::zero().write_le_bytes(&mut [0_u8; 15]),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        I128::zero().write_le_u32(&mut [0_u32; 3]),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        I128::zero().write_le_u64(&mut [0_u64; 1]),
        Err(ConversionError::BufferTooSmall)
    );
}

#[test]
fn negation_bitwise_not_and_shift_operator_forms_are_available() {
    let left = I128::from(0b1100_i8);
    let right = I128::from(0b1010_i8);

    macro_rules! assert_forms {
        ($operator:tt, $expected:expr) => {{
            assert_eq!(left $operator right, I128::from($expected));
            assert_eq!(left $operator &right, I128::from($expected));
            assert_eq!(&left $operator right, I128::from($expected));
            assert_eq!(&left $operator &right, I128::from($expected));
        }};
    }

    assert_forms!(&, 0b1000_i8);
    assert_forms!(|, 0b1110_i8);
    assert_forms!(^, 0b0110_i8);
    assert_eq!(-left, -&left);
    assert_eq!(!left, !&left);
    assert_eq!(left << 2, I128::from(48_i8));
    assert_eq!(&left << 2, I128::from(48_i8));
    assert_eq!(left >> 2, I128::from(3_i8));
    assert_eq!(&left >> 2, I128::from(3_i8));

    let mut assigned = I128::from(-1_i8);
    assigned &= &I128::from(0b1110_i8);
    assigned |= I128::from(1_i8);
    assigned ^= &I128::from(0b0101_i8);
    assigned <<= 2;
    assigned >>= 1;
    assert_eq!(assigned, I128::from(20_i8));
}

#[test]
fn numeric_trait_specific_paths_are_covered() {
    let value = I128::from(-5_i8);
    assert_eq!(Pow::pow(value, 2_u32), I128::from(25_i8));
    assert_eq!(Pow::pow(value, &2_u32), I128::from(25_i8));
    assert_eq!(Pow::pow(&value, 2_u32), I128::from(25_i8));
    assert_eq!(Pow::pow(&value, &2_u32), I128::from(25_i8));
    assert_eq!(I128::from_i64(-9), Some(I128::from(-9_i8)));
    assert_eq!(I128::from_i128(i128::MIN), Some(I128::from(i128::MIN)));
    assert_eq!(I128::from_u64(u64::MAX), Some(I128::from(u64::MAX)));
    assert_eq!(I128::from_u128(u128::MAX), None);
    assert_eq!(I128::from(i128::MIN).to_i128(), Some(i128::MIN));
    assert_eq!(I128::from(-1_i8).to_u64(), None);
    assert_eq!(I128::from(u64::MAX).to_u64(), Some(u64::MAX));
    assert_eq!(I128::from(-1_i8).to_u128(), None);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn set_bit_rejects_out_of_range_index() {
    let _ = I128::zero().set_bit(128);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn clear_bit_rejects_out_of_range_index() {
    let _ = I128::zero().clear_bit(128);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn flip_bit_rejects_out_of_range_index() {
    let _ = I128::zero().flip_bit(128);
}

#[test]
#[should_panic(expected = "attempted to negate with overflow")]
fn negation_rejects_minimum_value() {
    let _ = -I128::min_value();
}

#[test]
#[should_panic(expected = "attempted to shift left with overflow")]
fn left_shift_rejects_width_or_larger() {
    let _ = I128::from(1_i8) << 128;
}

#[test]
#[should_panic(expected = "attempted to shift right with overflow")]
fn right_shift_rejects_width_or_larger() {
    let _ = I128::from(1_i8) >> 128;
}

#[test]
#[should_panic(expected = "modulus must be positive")]
fn modular_power_rejects_non_positive_modulus() {
    let _ = I128::from(1_i8).mod_pow(&I128::from(2_i8), &I128::from(-3_i8));
}

#[test]
#[should_panic(expected = "base is not invertible for a negative exponent")]
fn negative_modular_power_rejects_a_non_invertible_base() {
    let _ = I128::from(2_i8).mod_pow(&I128::from(-1_i8), &I128::from(4_i8));
}
