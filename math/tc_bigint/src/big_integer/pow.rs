use super::BigInteger;
use crate::traits::Pow;

impl Pow<u32> for BigInteger {
    fn pow(&self, exponent: &u32) -> Self {
        BigInteger::pow(self, *exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::{BigInteger, Pow};

    #[test]
    fn big_integer_implements_pow() {
        let base = BigInteger::from_i32(-2);

        assert_eq!(Pow::pow(&base, &3), BigInteger::from_i32(-8));
    }
}
