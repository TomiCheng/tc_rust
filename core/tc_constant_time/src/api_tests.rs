use super::*;

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

macro_rules! unsigned_boundaries {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            let mut values = [0 as $t; 3 * <$t>::BITS as usize + 3];
            values[1] = <$t>::MAX;
            values[2] = 1;
            for bit in 0..<$t>::BITS {
                let power = (1 as $t) << bit;
                values[3 + 3 * bit as usize] = power;
                values[4 + 3 * bit as usize] = power.wrapping_sub(1);
                values[5 + 3 * bit as usize] = power.wrapping_add(1);
            }
            for a in values {
                for b in values {
                    assert_eq!(a.ct_eq(&b).unwrap_u8(), u8::from(a == b));
                    assert_eq!(a.ct_lt(&b).unwrap_u8(), u8::from(a < b));
                    assert_eq!(a.ct_gt(&b).unwrap_u8(), u8::from(a > b));
                    assert_eq!(a.ct_le(&b).unwrap_u8(), u8::from(a <= b));
                    assert_eq!(a.ct_ge(&b).unwrap_u8(), u8::from(a >= b));
                    for bit in 0..=1 {
                        let choice = Choice::from_lsb(bit);
                        assert_eq!(
                            <$t>::conditional_select(&a, &b, choice),
                            if bit == 0 { a } else { b }
                        );
                        let mut assigned = a;
                        assigned.conditional_assign(&b, choice);
                        assert_eq!(assigned, if bit == 0 { a } else { b });
                        let (mut left, mut right) = (a, b);
                        <$t>::conditional_swap(&mut left, &mut right, choice);
                        assert_eq!((left, right), if bit == 0 { (a, b) } else { (b, a) });
                        let mut negated = a;
                        negated.conditional_negate(choice);
                        assert_eq!(negated, if bit == 0 { a } else { a.wrapping_neg() });
                    }
                }
            }
        }
    };
}
unsigned_boundaries!(unsigned_u8_boundaries, u8);
unsigned_boundaries!(unsigned_u16_boundaries, u16);
unsigned_boundaries!(unsigned_u32_boundaries, u32);
unsigned_boundaries!(unsigned_u64_boundaries, u64);
unsigned_boundaries!(unsigned_u128_boundaries, u128);
unsigned_boundaries!(unsigned_usize_boundaries, usize);

macro_rules! signed_boundaries {
    ($name:ident, $t:ty) => {
        #[test]
        fn $name() {
            for bit in 0..<$t>::BITS {
                let power = (1 as $t) << bit;
                let values = [<$t>::MIN, <$t>::MIN + 1, -1, 0, 1, <$t>::MAX, power, !power];
                for a in values {
                    for b in values {
                        assert_eq!(a.ct_eq(&b).unwrap_u8(), u8::from(a == b));
                        for bit in 0..=1 {
                            let choice = Choice::from_lsb(bit);
                            assert_eq!(
                                <$t>::conditional_select(&a, &b, choice),
                                if bit == 0 { a } else { b }
                            );
                            let mut assigned = a;
                            assigned.conditional_assign(&b, choice);
                            assert_eq!(assigned, if bit == 0 { a } else { b });
                            let (mut left, mut right) = (a, b);
                            <$t>::conditional_swap(&mut left, &mut right, choice);
                            assert_eq!((left, right), if bit == 0 { (a, b) } else { (b, a) });
                            let mut negated = a;
                            negated.conditional_negate(choice);
                            assert_eq!(negated, if bit == 0 { a } else { a.wrapping_neg() });
                        }
                    }
                }
            }
        }
    };
}
signed_boundaries!(signed_i32_boundaries, i32);
signed_boundaries!(signed_i64_boundaries, i64);

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

#[test]
fn slices_scan_all_elements_but_can_reveal_public_length_mismatches() {
    use core::cell::Cell;
    struct Counted<'a>(u8, &'a Cell<usize>);
    impl ConstantTimeEq for Counted<'_> {
        fn ct_eq(&self, rhs: &Self) -> Choice {
            self.1.set(self.1.get() + 1);
            self.0.ct_eq(&rhs.0)
        }
    }
    let visits = Cell::new(0);
    let left = [
        Counted(1, &visits),
        Counted(2, &visits),
        Counted(3, &visits),
    ];
    let right = [
        Counted(9, &visits),
        Counted(2, &visits),
        Counted(3, &visits),
    ];
    assert_eq!(left[..].ct_eq(&right[..]).unwrap_u8(), 0);
    assert_eq!(visits.replace(0), 3);
    assert_eq!(left[..].ct_eq(&right[..2]).unwrap_u8(), 0);
    assert_eq!(visits.get(), 0);
    assert_eq!(left[..0].ct_eq(&right[..0]).unwrap_u8(), 1);
    assert_eq!(visits.get(), 0);
    assert!(!fixed_time_eq(b"prefix", b"prefix-extra"));
    assert!(!fixed_time_eq(b"prefix-extra", b"prefix"));
    assert!(fixed_time_eq(b"", b""));
}
