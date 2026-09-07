//! Cross-module tests for the parent integer type.

use super::*;
use crate::traits::{FromPrimitive, ToPrimitive};
use crate::{ParseBigIntError, Pow};

type U128 = FixedBigUint<{ 128 / Word::BITS as usize }>;

#[test]
fn external_units_are_full_width_and_little_endian() {
    let value = U128::from_le_u64(&[0x1122_3344_5566_7788]).unwrap();
    let mut bytes = [0_u8; 16];
    let mut words32 = [0_u32; 4];
    let mut words64 = [0_u64; 2];

    assert_eq!(value.write_le_bytes(&mut bytes), Ok(16));
    assert_eq!(
        &bytes[..8],
        &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );
    assert_eq!(value.write_le_u32(&mut words32), Ok(4));
    assert_eq!(words32, [0x5566_7788, 0x1122_3344, 0, 0]);
    assert_eq!(value.write_le_u64(&mut words64), Ok(2));
    assert_eq!(words64, [0x1122_3344_5566_7788, 0]);
}

#[test]
fn modular_power_does_not_allocate_or_overflow_intermediates() {
    let three = U128::from(3_u8);
    let seven = U128::from(7_u8);

    assert_eq!(three.mod_pow(&U128::from(4_u8), &seven), U128::from(4_u8));

    let max = U128::max_value();
    assert_eq!(
        (max - U128::from(1_u8)).mod_pow(&U128::from(2_u8), &max),
        U128::from(1_u8)
    );
}

#[test]
fn public_state_bit_and_parsing_methods_cover_normal_and_error_paths() {
    assert!(U128::default().is_zero());
    assert_eq!(
        U128::zero().as_limbs(),
        &[Limb::new(0); 128 / Word::BITS as usize]
    );
    assert_eq!(U128::max_value().bit_length(), 128);

    let value = U128::from(0b1010_u8);
    assert_eq!(value.bit_count(), 2);
    assert!(value.test_bit(3));
    assert!(!value.test_bit(128));
    assert_eq!(value.set_bit(0), U128::from(0b1011_u8));
    assert_eq!(value.clear_bit(3), U128::from(0b0010_u8));
    assert_eq!(value.flip_bit(1), U128::from(0b1000_u8));
    assert_eq!(value.lowest_set_bit(), Some(1));
    assert_eq!(U128::zero().lowest_set_bit(), None);
    assert_eq!(value.and_not(&U128::from(0b0011_u8)), U128::from(8_u8));

    assert_eq!(U128::from_str_radix("+FF", 16), Ok(U128::from(255_u16)));
    assert_eq!(
        U128::from_str_radix("-1", 10),
        Err(ParseBigIntError::NegativeUnsigned)
    );
    assert_eq!(
        U128::from_str_radix("", 10),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(
        U128::from_str_radix("?", 10),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(
        U128::from_str_radix("2", 2),
        Err(ParseBigIntError::InvalidDigit)
    );
    assert_eq!(
        U128::from_str_radix("1", 1),
        Err(ParseBigIntError::InvalidRadix)
    );
    assert_eq!(
        FixedBigUint::<1>::from_str_radix("1".repeat(Word::BITS as usize + 1).as_str(), 2),
        Err(ParseBigIntError::Overflow)
    );
}

#[test]
fn bounds_default_hash_and_leading_zeros_are_available() {
    use core::hash::{Hash, Hasher};

    struct Probe(u64);
    impl Hasher for Probe {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(*byte));
            }
        }
    }

    assert_eq!(U128::MIN, U128::zero());
    assert_eq!(U128::MAX, U128::max_value());
    assert_eq!(U128::default(), U128::MIN);
    assert_eq!(U128::zero().leading_zeros(), 128);
    assert_eq!(U128::from(1_u8).leading_zeros(), 127);
    let mut hasher = Probe(0);
    U128::from(1_u8).hash(&mut hasher);
    assert_ne!(hasher.finish(), 0);
}

#[test]
fn decoders_try_from_and_writers_cover_each_error_path() {
    assert_eq!(U128::from_le_bytes(&[1]), Ok(U128::from(1_u8)));
    assert_eq!(U128::from_le_u32(&[1]), Ok(U128::from(1_u8)));
    assert_eq!(U128::from_le_u64(&[1]), Ok(U128::from(1_u8)));
    assert_eq!(U128::try_from(&[1_u8][..]), Ok(U128::from(1_u8)));
    assert_eq!(U128::try_from(&[1_u32][..]), Ok(U128::from(1_u8)));
    assert_eq!(U128::try_from(&[1_u64][..]), Ok(U128::from(1_u8)));

    assert_eq!(
        FixedBigUint::<0>::from_le_bytes(&[1]),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        FixedBigUint::<0>::from_le_u32(&[1]),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        FixedBigUint::<0>::from_le_u64(&[1]),
        Err(ConversionError::InputTooLarge)
    );
    assert_eq!(
        U128::zero().write_le_bytes(&mut [0_u8; 15]),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        U128::zero().write_le_u32(&mut [0_u32; 3]),
        Err(ConversionError::BufferTooSmall)
    );
    assert_eq!(
        U128::zero().write_le_u64(&mut [0_u64; 1]),
        Err(ConversionError::BufferTooSmall)
    );
}

#[test]
fn bitwise_not_and_shift_operator_forms_are_all_available() {
    let left = U128::from(0b1100_u8);
    let right = U128::from(0b1010_u8);

    macro_rules! assert_forms {
        ($operator:tt, $expected:expr) => {{
            assert_eq!(left $operator right, U128::from($expected));
            assert_eq!(left $operator &right, U128::from($expected));
            assert_eq!(&left $operator right, U128::from($expected));
            assert_eq!(&left $operator &right, U128::from($expected));
        }};
    }

    assert_forms!(&, 0b1000_u8);
    assert_forms!(|, 0b1110_u8);
    assert_forms!(^, 0b0110_u8);
    assert_eq!(!left, !&left);
    assert_eq!(left << 2, U128::from(48_u8));
    assert_eq!(&left << 2, U128::from(48_u8));
    assert_eq!(left >> 2, U128::from(3_u8));
    assert_eq!(&left >> 2, U128::from(3_u8));

    let mut assigned = left;
    assigned &= &right;
    assigned |= U128::from(0b0011_u8);
    assigned ^= &U128::from(0b0101_u8);
    assigned <<= 2;
    assigned >>= 1;
    assert_eq!(assigned, U128::from(28_u8));
}

#[test]
fn numeric_trait_specific_paths_are_covered() {
    let value = U128::from(5_u8);
    assert_eq!(Pow::pow(value, 3_u32), U128::from(125_u8));
    assert_eq!(Pow::pow(value, &3_u32), U128::from(125_u8));
    assert_eq!(Pow::pow(&value, 3_u32), U128::from(125_u8));
    assert_eq!(Pow::pow(&value, &3_u32), U128::from(125_u8));
    assert_eq!(U128::from_i64(-1), None);
    assert_eq!(U128::from_i128(-1), None);
    assert_eq!(U128::from_u64(9), Some(U128::from(9_u8)));
    assert_eq!(U128::from_u128(u128::MAX), Some(U128::from(u128::MAX)));
    assert_eq!(U128::from(u64::MAX).to_i64(), None);
    assert_eq!(U128::from(u128::MAX).to_i128(), None);
    assert_eq!(U128::from(u64::MAX).to_u64(), Some(u64::MAX));
    assert_eq!(U128::from(u128::MAX).to_u128(), Some(u128::MAX));
}

#[test]
fn concat_reassembles_the_full_wide_product() {
    type Half = FixedBigUint<2>;
    type Wide = FixedBigUint<4>;

    let left = Half::max_value() - Half::from(7_u8);
    let right = Half::max_value() - Half::from(11_u8);
    let (low, high) = left.mul_wide(&right);

    assert_eq!(
        Wide::concat(&low, &high),
        Wide::widen_from(&left) * Wide::widen_from(&right)
    );
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn set_bit_rejects_out_of_range_index() {
    let _ = U128::zero().set_bit(128);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn clear_bit_rejects_out_of_range_index() {
    let _ = U128::zero().clear_bit(128);
}

#[test]
#[should_panic(expected = "bit index is outside fixed width")]
fn flip_bit_rejects_out_of_range_index() {
    let _ = U128::zero().flip_bit(128);
}

#[test]
#[should_panic(expected = "attempted to shift left with overflow")]
fn left_shift_rejects_width_or_larger() {
    let _ = U128::from(1_u8) << 128;
}

#[test]
#[should_panic(expected = "attempted to shift right with overflow")]
fn right_shift_rejects_width_or_larger() {
    let _ = U128::from(1_u8) >> 128;
}

#[test]
#[should_panic(expected = "modulus must be non-zero")]
fn modular_power_rejects_zero() {
    let _ = U128::from(1_u8).mod_pow(&U128::from(2_u8), &U128::zero());
}
