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
    1024 => { uint: U1024, int: I1024 },
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::{I1024, U1024};

    #[test]
    fn aliases_have_1024_bit_storage() {
        assert_eq!(size_of::<I1024>() * 8, 1024);
        assert_eq!(size_of::<U1024>() * 8, 1024);
    }
}
