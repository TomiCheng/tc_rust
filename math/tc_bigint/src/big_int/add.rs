//! Addition implementations for [`BigInt`].

use alloc::vec::Vec;
use core::borrow::Borrow;
use core::cmp::Ordering;
use core::ops::Add;

use super::{BigInt, compare_magnitude, sub_in_place, trim_leading_zeros};
use crate::Word;
use crate::magnitude::add_in_place;

impl<Rhs> Add<Rhs> for &BigInt
where
    Rhs: Borrow<BigInt>,
{
    type Output = BigInt;

    fn add(self, rhs: Rhs) -> BigInt {
        add_refs(self, rhs.borrow())
    }
}

impl<Rhs> Add<Rhs> for BigInt
where
    Rhs: Borrow<BigInt>,
{
    type Output = BigInt;

    fn add(self, rhs: Rhs) -> BigInt {
        add_owned(self, rhs.borrow())
    }
}

fn add_refs(lhs: &BigInt, rhs: &BigInt) -> BigInt {
    if lhs.sign == 0 {
        return rhs.clone();
    }
    if rhs.sign == 0 {
        return lhs.clone();
    }

    if lhs.sign == rhs.sign {
        if lhs.magnitude.len() >= rhs.magnitude.len() {
            add_owned(lhs.clone(), rhs)
        } else {
            add_owned(rhs.clone(), lhs)
        }
    } else {
        match compare_magnitude(&lhs.magnitude, &rhs.magnitude) {
            Ordering::Greater | Ordering::Equal => add_owned(lhs.clone(), rhs),
            Ordering::Less => add_owned(rhs.clone(), lhs),
        }
    }
}

fn add_owned(mut lhs: BigInt, rhs: &BigInt) -> BigInt {
    if rhs.sign == 0 {
        return lhs;
    }
    if lhs.sign == 0 {
        return rhs.clone();
    }

    if lhs.sign == rhs.sign {
        add_magnitude_in_place(&mut lhs.magnitude, &rhs.magnitude);
        return lhs;
    }

    match compare_magnitude(&lhs.magnitude, &rhs.magnitude) {
        Ordering::Greater => {
            sub_in_place(&mut lhs.magnitude, &rhs.magnitude);
            lhs.magnitude = trim_leading_zeros(lhs.magnitude);
            lhs
        }
        Ordering::Equal => {
            lhs.sign = 0;
            lhs.magnitude.clear();
            lhs
        }
        Ordering::Less => {
            let mut result = rhs.clone();
            sub_in_place(&mut result.magnitude, &lhs.magnitude);
            result.magnitude = trim_leading_zeros(result.magnitude);
            result
        }
    }
}

fn add_magnitude_in_place(x: &mut Vec<Word>, y: &[Word]) {
    let original_len = x.len();
    let result_len = original_len.max(y.len()) + 1;
    let offset = result_len - original_len;

    x.resize(result_len, 0);
    x.copy_within(..original_len, offset);
    x[..offset].fill(0);

    add_in_place(x, y);

    if x[0] == 0 {
        x.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::BigInt;

    #[test]
    fn supports_owned_and_borrowed_operands() {
        let lhs = BigInt::from_i32(20);
        let rhs = BigInt::from_i32(22);
        let expected = BigInt::from_i32(42);

        assert_eq!(&lhs + &rhs, expected);
        assert_eq!(&lhs + rhs.clone(), expected);
        assert_eq!(lhs.clone() + &rhs, expected);
        assert_eq!(lhs + rhs, expected);
    }

    #[test]
    fn supports_mixed_signs() {
        let lhs = BigInt::from_i32(20);
        let rhs = BigInt::from_i32(-22);
        let expected = BigInt::from_i32(-2);

        assert_eq!(&lhs + &rhs, expected);
        assert_eq!(&lhs + rhs.clone(), expected);
        assert_eq!(lhs.clone() + &rhs, expected);
        assert_eq!(lhs + rhs, expected);
    }

    #[test]
    fn carries_into_a_new_word() {
        let lhs = BigInt::from(crate::Word::MAX);
        let rhs = BigInt::from_u8(1);

        assert_eq!((lhs + rhs).magnitude, [1, 0]);
    }

    #[test]
    fn opposite_values_cancel_to_zero() {
        let lhs = BigInt::from_i32(42);
        let rhs = BigInt::from_i32(-42);
        let result = lhs + rhs;

        assert_eq!(result.sign, 0);
        assert!(result.magnitude.is_empty());
    }
}
