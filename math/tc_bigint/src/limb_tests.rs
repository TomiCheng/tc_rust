//! Retains the original limb module regression tests to validate the re-exported types.
#[cfg(test)]
mod tests {
    use crate::{Limb, Word};

    #[test]
    fn carrying_and_borrowing_report_the_extra_word() {
        assert_eq!(
            Limb::new(Word::MAX).carrying_add(Limb::new(0), Limb::new(1)),
            (Limb::new(0), Limb::new(1))
        );
        assert_eq!(
            Limb::new(0).borrowing_sub(Limb::new(Word::MAX), Limb::new(1)),
            (Limb::new(0), Limb::new(1))
        );
    }

    #[test]
    fn overflowing_and_wrapping_operations_match_word_arithmetic() {
        assert_eq!(
            Limb::new(Word::MAX).overflowing_add(Limb::new(1)),
            (Limb::new(0), true)
        );
        assert_eq!(
            Limb::new(0).overflowing_sub(Limb::new(1)),
            (Limb::new(Word::MAX), true)
        );
        assert_eq!(
            Limb::new(Word::MAX).wrapping_add(Limb::new(1)),
            Limb::new(0)
        );
        assert_eq!(
            Limb::new(0).wrapping_sub(Limb::new(1)),
            Limb::new(Word::MAX)
        );
    }

    #[test]
    #[should_panic(expected = "borrow must be zero or one")]
    fn borrowing_sub_rejects_a_non_bit_borrow() {
        let _ = Limb::new(0).borrowing_sub(Limb::new(0), Limb::new(2));
    }
}
