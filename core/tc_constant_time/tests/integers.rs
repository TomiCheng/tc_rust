use tc_constant_time::{
    Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeOrd,
};

#[test]
fn select_and_equal_all_bytes() {
    for a in 0..=255_u8 {
        for b in 0..=255_u8 {
            assert_eq!(u8::conditional_select(&a, &b, Choice::from_lsb(0)), a);
            assert_eq!(u8::conditional_select(&a, &b, Choice::from_lsb(1)), b);
            assert_eq!(a.ct_eq(&b).unwrap_u8(), (a == b) as u8);
        }
    }
}

macro_rules! wide_integer_tests {
    ($name:ident, $word:ty) => {
        #[test]
        fn $name() {
            for bit in 0..<$word>::BITS {
                let single = (1 as $word) << bit;
                let values = [0, 1, single, !single, <$word>::MAX];
                for a in values {
                    for b in values {
                        assert_eq!(<$word>::conditional_select(&a, &b, Choice::from_lsb(0)), a);
                        assert_eq!(<$word>::conditional_select(&a, &b, Choice::from_lsb(1)), b);
                        assert_eq!(a.ct_eq(&b).unwrap_u8(), u8::from(a == b));
                    }
                }
            }
        }
    };
}

wide_integer_tests!(select_and_equal_u32_bit_boundaries, u32);
wide_integer_tests!(select_and_equal_u64_bit_boundaries, u64);
wide_integer_tests!(select_and_equal_usize_bit_boundaries, usize);

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
                let values = [
                    <$t>::MIN,
                    <$t>::MIN + 1,
                    -1,
                    0,
                    1,
                    <$t>::MAX,
                    power,
                    !power,
                    power.wrapping_sub(1),
                    power.wrapping_add(1),
                    power.wrapping_neg(),
                ];
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
        }
    };
}
signed_boundaries!(signed_i8_boundaries, i8);
signed_boundaries!(signed_i16_boundaries, i16);
signed_boundaries!(signed_i32_boundaries, i32);
signed_boundaries!(signed_i64_boundaries, i64);
signed_boundaries!(signed_i128_boundaries, i128);
signed_boundaries!(signed_isize_boundaries, isize);

#[test]
fn exhaustive_signed_byte_api_matches_public_references() {
    for a in i8::MIN..=i8::MAX {
        for b in i8::MIN..=i8::MAX {
            assert_eq!(a.ct_eq(&b).unwrap_u8(), u8::from(a == b));
            assert_eq!(a.ct_lt(&b).unwrap_u8(), u8::from(a < b));
            assert_eq!(a.ct_gt(&b).unwrap_u8(), u8::from(a > b));
            assert_eq!(a.ct_le(&b).unwrap_u8(), u8::from(a <= b));
            assert_eq!(a.ct_ge(&b).unwrap_u8(), u8::from(a >= b));
            for bit in 0..=1 {
                let choice = Choice::from_lsb(bit);
                assert_eq!(
                    i8::conditional_select(&a, &b, choice),
                    if bit == 0 { a } else { b }
                );
                let mut assigned = a;
                assigned.conditional_assign(&b, choice);
                assert_eq!(assigned, if bit == 0 { a } else { b });
                let (mut left, mut right) = (a, b);
                i8::conditional_swap(&mut left, &mut right, choice);
                assert_eq!((left, right), if bit == 0 { (a, b) } else { (b, a) });
                let mut negated = a;
                negated.conditional_negate(choice);
                assert_eq!(negated, if bit == 0 { a } else { a.wrapping_neg() });
            }
        }
    }
}
