//! Common fixed-precision integer aliases.

use crate::{FixedBigInt, FixedBigUint, Word};

macro_rules! define_fixed_uints {
    ($($bits:literal => $name:ident),* $(,)?) => {
        $(
            #[doc = concat!("A fixed-precision ", stringify!($bits), "-bit unsigned integer.")]
            pub type $name = FixedBigUint<{ ($bits as usize).div_ceil(Word::BITS as usize) }>;
        )*
    };
}

macro_rules! define_fixed_ints {
    ($($bits:literal => $name:ident),* $(,)?) => {
        $(
            #[doc = concat!("A fixed-precision ", stringify!($bits), "-bit signed integer.")]
            pub type $name = FixedBigInt<{ $bits / Word::BITS as usize }>;
        )*
    };
}

define_fixed_uints! {
    64 => U64,
    128 => U128,
    256 => U256,
    384 => U384,
    521 => U521,
    1024 => U1024,
    2048 => U2048,
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
}
