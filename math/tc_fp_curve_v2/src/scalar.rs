use tc_bigint::{PaddedBigUint, Word};

fn width(scalar: &PaddedBigUint) -> usize {
    scalar.as_limbs().len() * Word::BITS as usize
}

pub(crate) fn bit_length(scalar: &PaddedBigUint) -> usize {
    scalar.bits() as usize
}

pub(crate) fn test_bit(scalar: &PaddedBigUint, index: usize) -> bool {
    index < width(scalar) && scalar.bit(index as u32)
}

pub(crate) fn is_zero(scalar: &PaddedBigUint) -> bool {
    scalar.bits() == 0
}

pub(crate) fn shr(scalar: &PaddedBigUint, count: usize) -> PaddedBigUint {
    if count >= width(scalar) {
        PaddedBigUint::from(0u8)
    } else {
        scalar >> count as u32
    }
}

pub(crate) fn low_bits(scalar: &PaddedBigUint, width: usize) -> u32 {
    assert!(width <= 32, "at most 32 low bits");
    (0..width).fold(0, |bits, i| bits | u32::from(test_bit(scalar, i)) << i)
}

pub(crate) fn sub_digit(scalar: &PaddedBigUint, digit: i32) -> PaddedBigUint {
    if digit >= 0 {
        scalar - digit.unsigned_abs()
    } else {
        scalar + digit.unsigned_abs()
    }
}
