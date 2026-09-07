use tc_constant_time::{Choice, ConditionallySelectable};

#[test]
fn default_assignment_and_swap_do_not_require_copy_or_clone() {
    struct Value(u64);
    impl ConditionallySelectable for Value {
        fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
            Self(u64::conditional_select(&a.0, &b.0, choice))
        }
    }
    for bit in 0..=1 {
        let choice = Choice::from_lsb(bit);
        let (mut a, mut b) = (Value(3), Value(7));
        Value::conditional_swap(&mut a, &mut b, choice);
        assert_eq!((a.0, b.0), if bit == 0 { (3, 7) } else { (7, 3) });
        a.conditional_assign(&Value(11), choice);
        assert_eq!(a.0, if bit == 0 { 3 } else { 11 });
    }
}
