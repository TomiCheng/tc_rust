//! Addition implementations for [`BigUint`].

use alloc::vec::Vec;
use core::ops::Add;

use super::BigUint;
use crate::Word;
use crate::magnitude::add_in_place;

impl Add<&BigUint> for &BigUint {
    type Output = BigUint;

    fn add(self, rhs: &BigUint) -> BigUint {
        if self.magnitude.len() >= rhs.magnitude.len() {
            add_owned(self.clone(), rhs)
        } else {
            add_owned(rhs.clone(), self)
        }
    }
}

impl Add<&BigUint> for BigUint {
    type Output = BigUint;

    fn add(self, rhs: &BigUint) -> BigUint {
        add_owned(self, rhs)
    }
}

impl Add<BigUint> for &BigUint {
    type Output = BigUint;

    fn add(self, rhs: BigUint) -> BigUint {
        add_owned(rhs, self)
    }
}

impl Add<BigUint> for BigUint {
    type Output = BigUint;

    fn add(self, rhs: BigUint) -> BigUint {
        if self.magnitude.is_empty() {
            return rhs;
        }
        if rhs.magnitude.is_empty() {
            return self;
        }

        if self.magnitude.capacity() >= rhs.magnitude.capacity() {
            add_owned(self, &rhs)
        } else {
            add_owned(rhs, &self)
        }
    }
}

fn add_owned(mut lhs: BigUint, rhs: &BigUint) -> BigUint {
    if rhs.magnitude.is_empty() {
        return lhs;
    }
    if lhs.magnitude.is_empty() {
        return rhs.clone();
    }

    add_magnitude_in_place(&mut lhs.magnitude, &rhs.magnitude);
    lhs
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
    use super::*;

    #[test]
    fn supports_owned_and_borrowed_operands() {
        let lhs = BigUint::from(20u8);
        let rhs = BigUint::from(22u8);

        assert_eq!((&lhs + &rhs).magnitude, [42]);
        assert_eq!((&lhs + rhs.clone()).magnitude, [42]);
        assert_eq!((lhs.clone() + &rhs).magnitude, [42]);
        assert_eq!((lhs + rhs).magnitude, [42]);
    }

    #[test]
    fn carries_into_a_new_word() {
        let lhs = BigUint::from(Word::MAX);
        let rhs = BigUint::from(1u8);

        assert_eq!((lhs + rhs).magnitude, [1, 0]);
    }

    #[test]
    fn adding_zero_preserves_the_other_operand() {
        let zero = BigUint::from(0u8);
        let value = BigUint::from(42u8);

        assert_eq!((&zero + &value).magnitude, [42]);
        assert_eq!((&value + &zero).magnitude, [42]);
    }
}
