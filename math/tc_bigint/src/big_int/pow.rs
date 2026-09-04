use super::BigInt;
use crate::traits::Pow;

impl Pow<u32> for BigInt {
    fn pow(&self, exponent: &u32) -> Self {
        BigInt::pow(self, *exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::{BigInt, Pow};

    #[test]
    fn big_int_implements_pow() {
        let base = BigInt::from_i32(-2);

        assert_eq!(Pow::pow(&base, &3), BigInt::from_i32(-8));
    }
}
