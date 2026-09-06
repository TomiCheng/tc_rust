//! 保留原 limb 模組的回歸測試，驗證重新匯出的型別。
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
    fn add_sub_and_assign_operators_work_without_overflow() {
        assert_eq!(Limb::new(2) + Limb::new(3), Limb::new(5));
        assert_eq!(Limb::new(5) - Limb::new(3), Limb::new(2));

        let mut value = Limb::new(5);
        value += Limb::new(4);
        value -= Limb::new(3);
        assert_eq!(value, Limb::new(6));
    }

    #[test]
    #[should_panic(expected = "attempted to add with overflow")]
    fn add_panics_on_overflow() {
        let _ = Limb::new(Word::MAX) + Limb::new(1);
    }

    #[test]
    #[should_panic(expected = "attempted to subtract with underflow")]
    fn sub_panics_on_underflow() {
        let _ = Limb::new(0) - Limb::new(1);
    }

    #[test]
    #[should_panic(expected = "borrow must be zero or one")]
    fn borrowing_sub_rejects_a_non_bit_borrow() {
        let _ = Limb::new(0).borrowing_sub(Limb::new(0), Limb::new(2));
    }
}
