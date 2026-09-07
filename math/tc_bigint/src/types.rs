//! Common fixed-precision integer aliases.

use crate::{FixedBigInt, FixedBigUint, Word};

/// Returns the limb count needed to store `bits` bits on the current target.
///
/// Limb width is a target detail: [`Word`](crate::Word) is 64 bits on 64-bit
/// targets and 32 bits elsewhere. Use this to size [`FixedBigUint`] and
/// [`FixedBigInt`] by bit width instead of restating the division.
///
/// ```
/// use tc_bigint::{FixedBigUint, limbs_for_bits};
/// type U2048 = FixedBigUint<{ limbs_for_bits(2048) }>;
/// assert_eq!(core::mem::size_of::<U2048>() * 8, 2048);
/// ```
pub const fn limbs_for_bits(bits: usize) -> usize {
    bits.div_ceil(Word::BITS as usize)
}

macro_rules! define_fixed_uints {
    ($($bits:literal => $name:ident),* $(,)?) => {
        $(
            #[doc = concat!("A fixed-precision ", stringify!($bits), "-bit unsigned integer.")]
            pub type $name = FixedBigUint<{ crate::limbs_for_bits($bits as usize) }>;
        )*
    };
}

macro_rules! define_fixed_ints {
    ($($bits:literal => $name:ident),* $(,)?) => {
        $(
            #[doc = concat!("A fixed-precision ", stringify!($bits), "-bit signed integer.")]
            pub type $name = FixedBigInt<{ crate::limbs_for_bits($bits as usize) }>;
        )*
    };
}

define_fixed_uints! {
    64 => U64,
    128 => U128,
    256 => U256,
    384 => U384,
    512 => U512,
    521 => U521,
    1024 => U1024,
    1536 => U1536,
    2048 => U2048,
    3072 => U3072,
    4096 => U4096,
}

define_fixed_ints! {
    64 => I64,
    128 => I128,
    1024 => I1024,
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{I64, I128, I1024, U64, U128, U256, U384, U521, U1024, U2048};
    use crate::FixedBigInt;

    define_fixed_ints! {
        521 => TestI521,
    }

    #[test]
    fn aliases_have_their_declared_storage_width() {
        assert_eq!(size_of::<I64>() * 8, 64);
        assert_eq!(size_of::<U64>() * 8, 64);
        assert_eq!(size_of::<I128>() * 8, 128);
        assert_eq!(size_of::<U128>() * 8, 128);
        assert_eq!(size_of::<U256>() * 8, 256);
        assert_eq!(size_of::<U384>() * 8, 384);
        assert_eq!(size_of::<I1024>() * 8, 1024);
        assert_eq!(size_of::<U1024>() * 8, 1024);
        assert_eq!(size_of::<U2048>() * 8, 2048);
    }

    #[test]
    fn u521_holds_a_521_bit_value() {
        let value = U521::from(1_u8).set_bit(520);

        assert_eq!(value.bit_length(), 521);
        assert!(size_of::<U521>() * 8 >= 521);
    }

    #[test]
    fn non_word_aligned_signed_alias_rounds_storage_up() {
        assert!(size_of::<TestI521>() * 8 >= 521);
    }
}
