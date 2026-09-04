//! Conversions from primitive signed integers.

use crate::{FixedBigInt, Limb, Word};

impl<const N: usize> FixedBigInt<N> {
    /// Creates a fixed-precision integer from an `i64`.
    ///
    /// Negative values are sign-extended across the remaining high limbs.
    ///
    /// # Panics
    ///
    /// Panics during constant evaluation when `N` is too small to contain all
    /// 64 bits of the input type.
    #[inline]
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        const {
            assert!(
                N >= 64 / Word::BITS as usize,
                "number of limbs is too small for i64"
            );
        }

        let extension = if value < 0 { Limb(Word::MAX) } else { Limb(0) };
        let mut limbs = [extension; N];

        #[cfg(target_pointer_width = "64")]
        {
            limbs[0] = Limb(value as Word);
        }

        #[cfg(not(target_pointer_width = "64"))]
        {
            let bits = value as u64;
            limbs[0] = Limb(bits as Word);
            limbs[1] = Limb((bits >> 32) as Word);
        }

        Self { limbs }
    }
}

#[cfg(test)]
mod tests {
    use crate::{I128, Limb, Word};

    const POSITIVE: I128 = I128::from_i64(0x1122_3344_5566_7788);
    const NEGATIVE: I128 = I128::from_i64(-2);

    #[test]
    fn from_i64_zero_extends_positive_values() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(POSITIVE.limbs, [Limb(0x1122_3344_5566_7788), Limb(0)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            POSITIVE.limbs,
            [Limb(0x5566_7788), Limb(0x1122_3344), Limb(0), Limb(0)]
        );
    }

    #[test]
    fn from_i64_sign_extends_negative_values() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(NEGATIVE.limbs, [Limb(Word::MAX - 1), Limb(Word::MAX)]);

        #[cfg(not(target_pointer_width = "64"))]
        assert_eq!(
            NEGATIVE.limbs,
            [
                Limb(Word::MAX - 1),
                Limb(Word::MAX),
                Limb(Word::MAX),
                Limb(Word::MAX),
            ]
        );
    }
}
