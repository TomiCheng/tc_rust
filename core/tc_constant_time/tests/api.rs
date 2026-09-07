use tc_constant_time::{
    Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd,
    fixed_time_eq,
};

#[test]
fn exhaustive_byte_api_matches_public_references() {
    for a in 0..=u8::MAX {
        for b in 0..=u8::MAX {
            assert_eq!(a.ct_lt(&b).unwrap_u8(), u8::from(a < b));
            assert_eq!(a.ct_gt(&b).unwrap_u8(), u8::from(a > b));
            assert_eq!(a.ct_le(&b).unwrap_u8(), u8::from(a <= b));
            assert_eq!(a.ct_ge(&b).unwrap_u8(), u8::from(a >= b));
            assert_eq!([a].as_slice().ct_eq(&[b][..]).unwrap_u8(), u8::from(a == b));
            assert_eq!(fixed_time_eq(&[a], &[b]), a == b);
            assert_eq!(
                (Choice::from_lsb(a) ^ Choice::from_lsb(b)).unwrap_u8(),
                (a ^ b) & 1
            );
            for bit in 0..=1 {
                let choice = Choice::from_lsb(bit);
                let mut assigned = a;
                assigned.conditional_assign(&b, choice);
                assert_eq!(assigned, if bit == 0 { a } else { b });
                let (mut left, mut right) = (a, b);
                u8::conditional_swap(&mut left, &mut right, choice);
                assert_eq!((left, right), if bit == 0 { (a, b) } else { (b, a) });
                let mut negated = a;
                negated.conditional_negate(choice);
                assert_eq!(negated, if bit == 0 { a } else { a.wrapping_neg() });
            }
        }
    }
}
