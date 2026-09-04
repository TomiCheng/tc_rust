//! Primitive integer conversions for [`BigUint`].

use alloc::{vec, vec::Vec};

use super::BigUint;
use crate::Word;

macro_rules! impl_from_small_unsigned {
    ($($t:ty),* $(,)?) => {
        $(
            impl From<$t> for BigUint {
                fn from(value: $t) -> Self {
                    let word = Word::from(value);
                    let magnitude = if word == 0 {
                        Vec::new()
                    } else {
                        vec![word]
                    };
                    Self { magnitude }
                }
            }
        )*
    };
}

impl_from_small_unsigned!(u8, u16, u32);

impl From<u64> for BigUint {
    fn from(value: u64) -> Self {
        #[cfg(target_pointer_width = "64")]
        let magnitude = if value == 0 { Vec::new() } else { vec![value] };

        #[cfg(not(target_pointer_width = "64"))]
        let magnitude = {
            let high = (value >> Word::BITS) as Word;
            let low = value as Word;
            if high != 0 {
                vec![high, low]
            } else if low != 0 {
                vec![low]
            } else {
                Vec::new()
            }
        };

        Self { magnitude }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_has_empty_magnitude() {
        assert!(BigUint::from(0u8).magnitude.is_empty());
        assert!(BigUint::from(0u16).magnitude.is_empty());
        assert!(BigUint::from(0u32).magnitude.is_empty());
        assert!(BigUint::from(0u64).magnitude.is_empty());
    }

    #[test]
    fn small_unsigned_values_use_one_word() {
        assert_eq!(BigUint::from(u8::MAX).magnitude, vec![Word::from(u8::MAX)]);
        assert_eq!(
            BigUint::from(u16::MAX).magnitude,
            vec![Word::from(u16::MAX)]
        );
        assert_eq!(
            BigUint::from(u32::MAX).magnitude,
            vec![Word::from(u32::MAX)]
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn u64_uses_one_word_on_64_bit_targets() {
        assert_eq!(BigUint::from(u64::MAX).magnitude, vec![u64::MAX]);
    }

    #[cfg(not(target_pointer_width = "64"))]
    #[test]
    fn u64_uses_two_words_on_32_bit_targets() {
        assert_eq!(
            BigUint::from(u64::MAX).magnitude,
            vec![Word::MAX, Word::MAX]
        );
    }
}
