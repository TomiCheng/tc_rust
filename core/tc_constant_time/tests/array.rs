use tc_constant_time::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

#[test]
fn arrays_select_and_compare_every_position() {
    let original = [0_u64, 1, 1 << 63, u64::MAX];
    assert_eq!(original.ct_eq(&original).unwrap_u8(), 1);
    for index in 0..original.len() {
        let mut changed = original;
        changed[index] ^= 1;
        assert_eq!(original.ct_eq(&changed).unwrap_u8(), 0);
        assert_eq!(changed.ct_eq(&original).unwrap_u8(), 0);
        assert_eq!(
            <[u64; 4]>::conditional_select(&original, &changed, Choice::from_lsb(0)),
            original
        );
        assert_eq!(
            <[u64; 4]>::conditional_select(&original, &changed, Choice::from_lsb(1)),
            changed
        );
    }
    let empty: [u64; 0] = [];
    assert_eq!(empty.ct_eq(&empty).unwrap_u8(), 1);
    for bit in 0..=1 {
        assert_eq!(
            <[u64; 0]>::conditional_select(&empty, &empty, Choice::from_lsb(bit)),
            empty
        );
    }
}

#[test]
fn arrays_support_in_place_operations_and_zero_length() {
    let left = [i32::MIN, -1, 0, i32::MAX];
    let right = [7, 11, -13, 17];
    for bit in 0..=1 {
        let choice = Choice::from_lsb(bit);
        let mut assigned = left;
        assigned.conditional_assign(&right, choice);
        assert_eq!(assigned, if bit == 0 { left } else { right });
        let (mut a, mut b) = (left, right);
        <[i32; 4]>::conditional_swap(&mut a, &mut b, choice);
        assert_eq!(
            (a, b),
            if bit == 0 {
                (left, right)
            } else {
                (right, left)
            }
        );
        let mut negated = left;
        negated.conditional_negate(choice);
        assert_eq!(
            negated,
            if bit == 0 {
                left
            } else {
                left.map(i32::wrapping_neg)
            }
        );
        let (mut empty_a, mut empty_b): ([i32; 0], [i32; 0]) = ([], []);
        empty_a.conditional_assign(&empty_b, choice);
        <[i32; 0]>::conditional_swap(&mut empty_a, &mut empty_b, choice);
        empty_a.conditional_negate(choice);
        assert_eq!(empty_a.ct_eq(&empty_b).unwrap_u8(), 1);
    }
}
