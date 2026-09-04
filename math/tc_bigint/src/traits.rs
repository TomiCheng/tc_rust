/// The standard addition operator trait, re-exported for generic big-integer code.
pub use core::ops::Add;

/// Raises a value to an integer power.
pub trait Pow<Exponent> {
    /// Returns `self` raised to `exponent`.
    fn pow(&self, exponent: &Exponent) -> Self;
}

#[cfg(test)]
mod tests {
    use crate::{Add, BigInt};

    fn add<L, R>(lhs: L, rhs: R) -> <L as Add<R>>::Output
    where
        L: Add<R>,
    {
        lhs + rhs
    }

    #[test]
    fn add_is_exposed_for_generic_code() {
        let lhs = BigInt::from_i32(20);
        let rhs = BigInt::from_i32(22);

        assert_eq!(add(&lhs, &rhs), BigInt::from_i32(42));
    }
}
