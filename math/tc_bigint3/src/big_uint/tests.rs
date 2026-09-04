//! Cross-module tests for the parent integer type.

use super::*;
use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{FixedBigUint, ParseBigIntError, Pow, Word};
use alloc::string::ToString;

#[test]
fn radix_round_trip() {
    assert_eq!(
        BigUint::from_str_radix("ff", 16).unwrap(),
        BigUint::from(255_u16)
    );
}

#[test]
fn external_units_are_little_endian() {
    let value = BigUint::from_le_bytes(&[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]);

    assert_eq!(
        value.to_le_bytes(),
        [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );
    assert_eq!(value.to_le_u32(), [0x5566_7788, 0x1122_3344]);
    assert_eq!(value.to_le_u64(), [0x1122_3344_5566_7788]);
}

#[test]
fn modular_power_matches_known_value() {
    let three = BigUint::from(3_u8);
    let seven = BigUint::from(7_u8);

    assert_eq!(
        three.mod_pow(&BigUint::from(4_u8), &seven),
        BigUint::from(4_u8)
    );
}

#[test]
fn bit_operations_match_the_le_value() {
    let value = BigUint::from(0b101100_u8);

    assert_eq!(value.bits(), 6);
    assert_eq!(value.bit_count(), 3);
    assert_eq!(value.lowest_set_bit(), Some(2));
    assert_eq!(value.set_bit(0), BigUint::from(0b101101_u8));
    assert_eq!(value.clear_bit(3), BigUint::from(0b100100_u8));
    assert_eq!(value.flip_bit(2), BigUint::from(0b101000_u8));
}

#[test]
fn setting_or_flipping_a_low_bit_preserves_existing_high_limbs() {
    let high = Word::BITS as usize * 2 - 1;
    let value = BigUint::one().set_bit(high);

    let set = value.set_bit(0);
    assert!(set.test_bit(high));
    assert!(set.test_bit(0));
    assert_eq!(set.bits(), high + 1);

    let flipped = value.flip_bit(1);
    assert!(flipped.test_bit(high));
    assert!(flipped.test_bit(1));
    assert_eq!(flipped.bits(), high + 1);
}

#[test]
fn conversion_writers_and_fixed_width_bridge_cover_success_and_errors() {
    let value = BigUint::from_le_u32(&[0x5566_7788, 0x1122_3344]);
    assert_eq!(
        value.as_limbs(),
        BigUint::from_le_u64(&[0x1122_3344_5566_7788]).as_limbs()
    );

    let mut bytes = [0_u8; 8];
    let mut words32 = [0_u32; 2];
    let mut words64 = [0_u64; 1];
    assert_eq!(value.write_le_bytes(&mut bytes), Ok(8));
    assert_eq!(value.write_le_u32(&mut words32), Ok(2));
    assert_eq!(value.write_le_u64(&mut words64), Ok(1));
    assert_eq!(BigUint::from(&bytes[..]), value);
    assert_eq!(BigUint::from(&words32[..]), value);
    assert_eq!(BigUint::from(&words64[..]), value);

    assert_eq!(
        value.write_le_bytes(&mut [0_u8; 7]),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        value.write_le_u32(&mut [0_u32; 1]),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        value.write_le_u64(&mut []),
        Err(ConversionError::BufferTooSmall)
    );

    type U = FixedBigUint<2>;
    let fixed = U::try_from(&value).expect("value fits");
    assert_eq!(BigUint::from(fixed), value);
    assert_eq!(
        FixedBigUint::<1>::try_from(&BigUint::from_le_u64(&[0, 1])),
        Err(ConversionError::InputTooLarge)
    );
}

#[test]
fn bitwise_and_shift_operators_support_all_ownership_forms() {
    let left = BigUint::from(0b1100_u8);
    let right = BigUint::from(0b1010_u8);

    macro_rules! assert_forms {
        ($operator:tt, $expected:expr) => {{
            assert_eq!(&left $operator &right, BigUint::from($expected));
            assert_eq!(&left $operator right.clone(), BigUint::from($expected));
            assert_eq!(left.clone() $operator &right, BigUint::from($expected));
            assert_eq!(left.clone() $operator right.clone(), BigUint::from($expected));
        }};
    }

    assert_forms!(&, 0b1000_u8);
    assert_forms!(|, 0b1110_u8);
    assert_forms!(^, 0b0110_u8);
    assert_eq!(&left << 2, BigUint::from(48_u8));
    assert_eq!(left.clone() << 2, BigUint::from(48_u8));
    assert_eq!(&left >> 2, BigUint::from(3_u8));
    assert_eq!(left >> 2, BigUint::from(3_u8));

    let mut assigned = BigUint::from(0b1100_u8);
    assigned &= &BigUint::from(0b1010_u8);
    assigned |= BigUint::from(0b0011_u8);
    assigned ^= &BigUint::from(0b0101_u8);
    assigned <<= 2;
    assigned >>= 1;
    assert_eq!(assigned, BigUint::from(28_u8));
}

#[test]
fn parsing_formatting_comparison_and_edge_bit_operations_are_covered() {
    assert!(BigUint::zero().is_zero());
    assert_eq!(BigUint::zero().to_str_radix(2), "0");
    assert_eq!(BigUint::from(255_u16).to_str_radix(16), "ff");
    assert_eq!(BigUint::from(42_u8).to_string(), "42");
    assert!(BigUint::from(2_u8) < BigUint::from(3_u8));

    assert_eq!(
        BigUint::from_str_radix("", 10),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(
        BigUint::from_str_radix("2", 2),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(
        BigUint::from_str_radix("-1", 10),
        Err(ParseBigIntError::NegativeUnsigned)
    );
    assert_eq!(
        BigUint::from_str_radix("1", 1),
        Err(ParseBigIntError::InvalidRadix)
    );

    let zero = BigUint::zero();
    assert!(!zero.test_bit(100));
    assert_eq!(zero.lowest_set_bit(), None);
    assert_eq!(zero.clear_bit(100), zero);
    assert!(zero.flip_bit(100).test_bit(100));
    assert_eq!(
        BigUint::from(0b1111_u8).and_not(&BigUint::from(0b0101_u8)),
        BigUint::from(0b1010_u8)
    );
}

#[test]
fn conversion_traits_cover_dynamic_unsigned_specific_paths() {
    let value = BigUint::from(5_u8);
    assert_eq!(Pow::pow(value.clone(), &3_u32), BigUint::from(125_u8));
    assert_eq!(Pow::pow(&value, 3_u32), BigUint::from(125_u8));
    assert_eq!(Pow::pow(&value, &3_u32), BigUint::from(125_u8));

    assert_eq!(BigUint::from_i64(-1), None);
    assert_eq!(BigUint::from_i128(-1), None);
    assert_eq!(BigUint::from_u64(9), Some(BigUint::from(9_u8)));
    assert_eq!(
        BigUint::from_u128(u128::MAX),
        Some(BigUint::from(u128::MAX))
    );
    assert_eq!(BigUint::from(u128::MAX).to_i128(), None);
    assert_eq!(BigUint::from(u64::MAX).to_i64(), None);
    assert_eq!(BigUint::from(u64::MAX).to_u64(), Some(u64::MAX));
    assert_eq!(BigUint::from(u128::MAX).to_u128(), Some(u128::MAX));
    assert_eq!(BigUint::from_le_u64(&[0, 0, 1]).to_u128(), None);
}

#[test]
#[should_panic(expected = "radix must be in 2..=36")]
fn formatting_panics_for_an_invalid_radix() {
    let _ = BigUint::from(1_u8).to_str_radix(37);
}

#[test]
#[should_panic(expected = "modulus must be non-zero")]
fn modular_power_rejects_a_zero_modulus() {
    let _ = BigUint::from(1_u8).mod_pow(&BigUint::from(2_u8), &BigUint::zero());
}
