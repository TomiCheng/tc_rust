use core::borrow::Borrow;
use core::ops::Add;

use super::{BigInteger, add_magnitudes};

impl<Rhs> Add<Rhs> for &BigInteger
where
    Rhs: Borrow<BigInteger>,
{
    type Output = BigInteger;

    fn add(self, rhs: Rhs) -> BigInteger {
        add(self, rhs.borrow())
    }
}

impl<Rhs> Add<Rhs> for BigInteger
where
    Rhs: Borrow<BigInteger>,
{
    type Output = BigInteger;

    fn add(self, rhs: Rhs) -> BigInteger {
        add(&self, rhs.borrow())
    }
}

fn add(lhs: &BigInteger, rhs: &BigInteger) -> BigInteger {
    if lhs.sign == 0 {
        rhs.clone()
    } else if rhs.sign == 0 {
        lhs.clone()
    } else if lhs.sign == rhs.sign {
        // 同號：magnitude 相加，沿用符號
        BigInteger::new(lhs.sign, add_magnitudes(&lhs.magnitude, &rhs.magnitude))
    } else if rhs.sign < 0 {
        lhs - &(-rhs)
    } else {
        rhs - &(-lhs)
    }
}

#[cfg(test)]
mod tests {
    use super::BigInteger;

    #[test]
    fn supports_owned_and_borrowed_operands() {
        let lhs = BigInteger::from_i32(20);
        let rhs = BigInteger::from_i32(22);
        let expected = BigInteger::from_i32(42);

        assert_eq!(&lhs + &rhs, expected);
        assert_eq!(&lhs + rhs.clone(), expected);
        assert_eq!(lhs.clone() + &rhs, expected);
        assert_eq!(lhs + rhs, expected);
    }
}
