//! Cross-module tests for the parent integer type.

use super::*;
use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{FixedBigInt, ParseBigIntError, Pow};
use alloc::string::ToString;

#[test]
fn signed_external_units_round_trip() {
    for value in [i128::MIN, -129, -128, -1, 0, 1, 127, 128, i128::MAX] {
        let value = BigInt::from(value);
        assert_eq!(BigInt::from_le_bytes(&value.to_le_bytes()), value);
        assert_eq!(BigInt::from_le_u32(&value.to_le_u32()), value);
        assert_eq!(BigInt::from_le_u64(&value.to_le_u64()), value);
    }
}

#[test]
fn right_shift_is_arithmetic() {
    assert_eq!((BigInt::from(-3_i8) >> 1).to_i64(), Some(-2));
    assert_eq!((BigInt::from(3_i8) >> 1).to_i64(), Some(1));
}

#[test]
fn bitwise_operations_use_infinite_sign_extension() {
    let minus_one = BigInt::from(-1_i8);
    let value = BigInt::from(0x1234_u16);

    assert_eq!((&minus_one & &value), value);
    assert_eq!((&minus_one | &value), minus_one);
    assert_eq!((&minus_one ^ &value).to_i64(), Some(!0x1234_i64));
}

#[test]
fn number_theory_operations_match_known_values() {
    let three = BigInt::from(3_i8);
    let seven = BigInt::from(7_i8);

    assert_eq!(
        BigInt::from(-12_i8).gcd(&BigInt::from(18_i8)),
        BigInt::from(6_i8)
    );
    assert_eq!(BigInt::from(-7_i8).rem_euclid(&three), BigInt::from(2_i8));
    assert_eq!(three.mod_inverse(&seven), Some(BigInt::from(5_i8)));
    assert_eq!(
        three.mod_pow(&BigInt::from(4_i8), &seven),
        BigInt::from(4_i8)
    );
    assert_eq!(
        three.mod_pow(&BigInt::from(-1_i8), &seven),
        BigInt::from(5_i8)
    );
}

#[test]
fn signed_bit_inspection_matches_twos_complement() {
    let value = BigInt::from(-8_i8);

    assert_eq!(value.bit_length(), 3);
    assert_eq!(value.bit_count(), 3);
    assert_eq!(value.lowest_set_bit(), Some(3));
    assert!(value.test_bit(100));
    assert_eq!(value.clear_bit(3), BigInt::from(-16_i8));
}

#[test]
fn conversion_writers_and_fixed_width_bridge_cover_signed_and_unsigned_inputs() {
    let negative = BigInt::from_le_bytes(&[0xfe]);
    assert_eq!(negative, BigInt::from(-2_i8));
    assert_eq!(BigInt::from(&[0xfe_u8][..]), negative);
    assert_eq!(BigInt::from(&[u32::MAX - 1][..]), negative);
    assert_eq!(BigInt::from(&[u64::MAX - 1][..]), negative);
    assert_eq!(
        BigInt::from_unsigned_le_bytes(&[0xfe]),
        BigInt::from(254_u8)
    );
    assert_eq!(
        BigInt::from_unsigned_le_u32(&[u32::MAX]),
        BigInt::from(u32::MAX)
    );
    assert_eq!(
        BigInt::from_unsigned_le_u64(&[u64::MAX]),
        BigInt::from(u64::MAX)
    );

    let mut bytes = [0_u8; 1];
    let mut words32 = [0_u32; 1];
    let mut words64 = [0_u64; 1];
    assert_eq!(negative.write_le_bytes(&mut bytes), Ok(1));
    assert_eq!(negative.write_le_u32(&mut words32), Ok(1));
    assert_eq!(negative.write_le_u64(&mut words64), Ok(1));
    assert_eq!(bytes, [0xfe]);
    assert_eq!(
        negative.write_le_bytes(&mut []),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        negative.write_le_u32(&mut []),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        negative.write_le_u64(&mut []),
        Err(ConversionError::BufferTooSmall)
    );

    type I = FixedBigInt<2>;
    let fixed = I::try_from(&negative).expect("minus two fits");
    assert_eq!(BigInt::from(fixed), negative);
    assert_eq!(
        FixedBigInt::<0>::try_from(&BigInt::zero()),
        Ok(FixedBigInt::zero())
    );
    assert_eq!(
        FixedBigInt::<0>::try_from(&negative),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        FixedBigInt::<1>::try_from(&(BigInt::one() << Word::BITS as usize)),
        Err(ConversionError::InputTooLarge)
    );
}

#[test]
fn negation_bitwise_and_shift_operators_cover_all_ownership_forms() {
    let left = BigInt::from(0b1100_i8);
    let right = BigInt::from(0b1010_i8);

    macro_rules! assert_forms {
        ($operator:tt, $expected:expr) => {{
            assert_eq!(&left $operator &right, BigInt::from($expected));
            assert_eq!(&left $operator right.clone(), BigInt::from($expected));
            assert_eq!(left.clone() $operator &right, BigInt::from($expected));
            assert_eq!(left.clone() $operator right.clone(), BigInt::from($expected));
        }};
    }

    assert_forms!(&, 0b1000_i8);
    assert_forms!(|, 0b1110_i8);
    assert_forms!(^, 0b0110_i8);
    assert_eq!(-&left, BigInt::from(-12_i8));
    assert_eq!(-left.clone(), BigInt::from(-12_i8));
    assert_eq!(!&left, BigInt::from(!12_i8));
    assert_eq!(!left.clone(), BigInt::from(!12_i8));
    assert_eq!(&left << 2, BigInt::from(48_i8));
    assert_eq!(left.clone() << 2, BigInt::from(48_i8));
    assert_eq!(&left >> 2, BigInt::from(3_i8));
    assert_eq!(left >> 2, BigInt::from(3_i8));

    let mut assigned = BigInt::from(-1_i8);
    assigned &= &BigInt::from(0b1110_i8);
    assigned |= BigInt::from(1_i8);
    assigned ^= &BigInt::from(0b0101_i8);
    assigned <<= 2;
    assigned >>= 1;
    assert_eq!(assigned, BigInt::from(20_i8));
}

#[test]
fn parsing_formatting_comparison_and_remaining_bit_operations_are_covered() {
    assert_eq!(BigInt::from_str_radix("+7f", 16), Ok(BigInt::from(127_i8)));
    assert_eq!(BigInt::from_str_radix("-7f", 16), Ok(BigInt::from(-127_i8)));
    assert_eq!(
        BigInt::from_str_radix("", 10),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(BigInt::from(-42_i8).to_str_radix(10), "-42");
    assert_eq!(BigInt::from(-42_i8).to_string(), "-42");
    assert!(BigInt::zero().is_zero());
    assert!(!BigInt::zero().is_negative());
    assert_eq!(BigInt::from(-7_i8).abs(), BigInt::from(7_i8));

    let value = BigInt::from(0b1010_i8);
    assert_eq!(value.set_bit(0), BigInt::from(0b1011_i8));
    assert_eq!(value.flip_bit(1), BigInt::from(0b1000_i8));
    assert_eq!(
        value.and_not(&BigInt::from(0b0011_i8)),
        BigInt::from(0b1000_i8)
    );
    assert_eq!(BigInt::zero().lowest_set_bit(), None);
    assert!(!BigInt::zero().test_bit(100));
}

#[test]
fn conversion_traits_cover_dynamic_signed_specific_paths() {
    let value = BigInt::from(-5_i8);
    assert_eq!(Pow::pow(value.clone(), &2_u32), BigInt::from(25_i8));
    assert_eq!(Pow::pow(&value, 2_u32), BigInt::from(25_i8));
    assert_eq!(Pow::pow(&value, &2_u32), BigInt::from(25_i8));

    assert_eq!(BigInt::from_i64(-9), Some(BigInt::from(-9_i8)));
    assert_eq!(BigInt::from_i128(i128::MIN), Some(BigInt::from(i128::MIN)));
    assert_eq!(BigInt::from_u64(u64::MAX), Some(BigInt::from(u64::MAX)));
    assert_eq!(BigInt::from_u128(u128::MAX), Some(BigInt::from(u128::MAX)));
    assert_eq!(BigInt::from(i128::MIN).to_i128(), Some(i128::MIN));
    assert_eq!(BigInt::from(-1_i8).to_u128(), None);
    assert_eq!(BigInt::from(u128::MAX).to_i128(), None);
    assert_eq!(BigInt::from(u64::MAX).to_u64(), Some(u64::MAX));
}

#[test]
#[should_panic(expected = "modulus must be positive")]
fn modular_inverse_rejects_non_positive_modulus() {
    let _ = BigInt::from(1_i8).mod_inverse(&BigInt::zero());
}

#[test]
#[should_panic(expected = "modulus must be positive")]
fn modular_power_rejects_non_positive_modulus() {
    let _ = BigInt::from(1_i8).mod_pow(&BigInt::from(2_i8), &BigInt::from(-3_i8));
}

#[test]
#[should_panic(expected = "base is not invertible for a negative exponent")]
fn negative_modular_power_rejects_a_non_invertible_base() {
    let _ = BigInt::from(2_i8).mod_pow(&BigInt::from(-1_i8), &BigInt::from(4_i8));
}
