//! Common fixed-precision integer aliases.

use crate::{FixedBigInt, FixedBigUint, Word};

macro_rules! define_fixed_types {
    (
        $(
            $bits:literal => {
                uint: $uint:ident,
                int: $int:ident
            }
        ),* $(,)?
    ) => {
        $(
            #[doc = concat!("A fixed-precision ", stringify!($bits), "-bit unsigned integer.")]
            pub type $uint = FixedBigUint<{ $bits / Word::BITS as usize }>;

            #[doc = concat!("A fixed-precision ", stringify!($bits), "-bit signed integer.")]
            pub type $int = FixedBigInt<{ $bits / Word::BITS as usize }>;
        )*
    };
}

define_fixed_types! {
    64 => { uint: U64, int: I64 },
    128 => { uint: U128, int: I128 },
    1024 => { uint: U1024, int: I1024 },
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{I64, I128, I1024, U64, U128, U1024};

    #[test]
    fn aliases_have_their_declared_storage_width() {
        assert_eq!(size_of::<I64>() * 8, 64);
        assert_eq!(size_of::<U64>() * 8, 64);
        assert_eq!(size_of::<I128>() * 8, 128);
        assert_eq!(size_of::<U128>() * 8, 128);
        assert_eq!(size_of::<I1024>() * 8, 1024);
        assert_eq!(size_of::<U1024>() * 8, 1024);
    }
}
