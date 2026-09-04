use core::borrow::Borrow;
use core::ops::Add;

use super::{BigInt, add_magnitudes};

impl<Rhs> Add<Rhs> for &BigInt
where
    Rhs: Borrow<BigInt>,
{
    type Output = BigInt;

    fn add(self, rhs: Rhs) -> BigInt {
        add(self, rhs.borrow())
    }
}

impl<Rhs> Add<Rhs> for BigInt
where
    Rhs: Borrow<BigInt>,
{
    type Output = BigInt;

    fn add(self, rhs: Rhs) -> BigInt {
        add(&self, rhs.borrow())
    }
}

fn add(lhs: &BigInt, rhs: &BigInt) -> BigInt {
    if lhs.sign == 0 {
        rhs.clone()
    } else if rhs.sign == 0 {
        lhs.clone()
    } else if lhs.sign == rhs.sign {
        // 同號：magnitude 相加，沿用符號
        BigInt::new(lhs.sign, add_magnitudes(&lhs.magnitude, &rhs.magnitude))
    } else if rhs.sign < 0 {
        lhs - &(-rhs)
    } else {
        rhs - &(-lhs)
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
}
