//! Arithmetic, modular and bit operations specific to big integers.

/// Exponentiation with a caller-selected exponent type.
pub trait Pow<Rhs> {
    /// Result type.
    type Output;

    /// Raises `self` to `rhs`.
    fn pow(self, rhs: Rhs) -> Self::Output;
}

/// Squaring without requiring the caller to clone the operand.
pub trait Square {
    /// Squared value.
    type Output;

    /// Returns `self * self`.
    fn square(&self) -> Self::Output;
}

/// A combined quotient-and-remainder operation.
pub trait DivRem<Rhs = Self> {
    /// Quotient type.
    type Quotient;
    /// Remainder type.
    type Remainder;

    /// Returns the quotient and remainder together.
    fn div_rem(&self, rhs: &Rhs) -> (Self::Quotient, Self::Remainder);
}

/// Euclidean remainder, which is non-negative for signed values.
pub trait RemEuclid<Rhs = Self> {
    /// Remainder type.
    type Output;

    /// Returns the least non-negative remainder.
    fn rem_euclid(&self, rhs: &Rhs) -> Self::Output;
}

/// Greatest common divisor.
pub trait Gcd<Rhs = Self> {
    /// GCD result type.
    type Output;

    /// Returns the non-negative greatest common divisor.
    fn gcd(&self, rhs: &Rhs) -> Self::Output;
}

/// Modular multiplicative inverse.
pub trait ModInverse<Modulus = Self> {
    /// Inverse type.
    type Output;

    /// Returns `x` such that `self * x = 1 (mod modulus)`, when it exists.
    fn mod_inverse(&self, modulus: &Modulus) -> Option<Self::Output>;
}

/// Modular exponentiation.
pub trait ModPow<Exponent = Self, Modulus = Self> {
    /// Modular exponentiation result type.
    type Output;

    /// Returns `self^exponent mod modulus`.
    fn mod_pow(&self, exponent: &Exponent, modulus: &Modulus) -> Self::Output;
}

/// Addition reduced modulo a non-zero modulus.
pub trait ModAdd<Rhs = Self, Modulus = Self> {
    /// Reduced result type.
    type Output;

    /// Returns `(self + rhs) mod modulus`.
    ///
    /// ```
    /// use tc_bigint::{ModAdd, U128};
    /// assert_eq!(U128::from(100_u8).mod_add(&U128::from(5_u8), &U128::from(101_u8)), U128::from(4_u8));
    /// ```
    fn mod_add(&self, rhs: &Rhs, modulus: &Modulus) -> Self::Output;
}

/// Subtraction reduced to the least non-negative residue.
pub trait ModSub<Rhs = Self, Modulus = Self> {
    /// Reduced result type.
    type Output;

    /// Returns `(self - rhs) mod modulus`.
    ///
    /// ```
    /// use tc_bigint::{ModSub, U128};
    /// assert_eq!(U128::from(3_u8).mod_sub(&U128::from(5_u8), &U128::from(101_u8)), U128::from(99_u8));
    /// ```
    fn mod_sub(&self, rhs: &Rhs, modulus: &Modulus) -> Self::Output;
}

/// Multiplication reduced modulo a non-zero modulus.
pub trait ModMul<Rhs = Self, Modulus = Self> {
    /// Reduced result type.
    type Output;

    /// Returns `(self * rhs) mod modulus` without requiring a full-width
    /// intermediate result from the caller.
    ///
    /// ```
    /// use tc_bigint::{ModMul, U128};
    /// assert_eq!(U128::MAX.mod_mul(&U128::MAX, &U128::from(101_u8)), U128::from(80_u8));
    /// ```
    fn mod_mul(&self, rhs: &Rhs, modulus: &Modulus) -> Self::Output;
}

/// Common bit inspection and mutation operations.
pub trait BitOps {
    /// Result of the non-mutating bit operations.
    type Output;

    /// Returns the significant bit length.
    fn bit_length(&self) -> usize;

    /// Returns the number of bits which differ from sign extension.
    fn bit_count(&self) -> usize;

    /// Tests bit `index`.
    fn test_bit(&self, index: usize) -> bool;

    /// Returns a value with bit `index` set.
    fn set_bit(&self, index: usize) -> Self::Output;

    /// Returns a value with bit `index` cleared.
    fn clear_bit(&self, index: usize) -> Self::Output;

    /// Returns a value with bit `index` flipped.
    fn flip_bit(&self, index: usize) -> Self::Output;

    /// Returns the index of the least-significant set bit.
    fn lowest_set_bit(&self) -> Option<usize>;
}

/// Computes `self & !rhs`.
pub trait AndNot<Rhs = Self> {
    /// Result type.
    type Output;

    /// Clears every bit which is set in `rhs`.
    fn and_not(&self, rhs: &Rhs) -> Self::Output;
}

#[cfg(test)]
mod tests {
    use super::{AndNot, BitOps, DivRem, Gcd, ModInverse, ModPow, Pow, RemEuclid, Square};
    use crate::{FixedBigUint, Word};

    type U = FixedBigUint<{ 128 / Word::BITS as usize }>;

    #[test]
    fn arithmetic_contracts_delegate_to_the_integer_implementations() {
        let seven = U::from(7_u8);
        let three = U::from(3_u8);
        let eleven = U::from(11_u8);

        assert_eq!(Pow::pow(seven, 2_u32), U::from(49_u8));
        assert_eq!(Pow::pow(&seven, &2_u32), U::from(49_u8));
        assert_eq!(Square::square(&seven), U::from(49_u8));
        assert_eq!(
            DivRem::div_rem(&seven, &three),
            (U::from(2_u8), U::from(1_u8))
        );
        assert_eq!(RemEuclid::rem_euclid(&seven, &three), U::from(1_u8));
        assert_eq!(Gcd::gcd(&U::from(21_u8), &U::from(6_u8)), U::from(3_u8));
        assert_eq!(
            ModInverse::mod_inverse(&three, &eleven),
            Some(U::from(4_u8))
        );
        assert_eq!(
            ModPow::mod_pow(&three, &U::from(4_u8), &eleven),
            U::from(4_u8)
        );
    }

    #[test]
    fn bit_operation_contracts_cover_each_method() {
        let value = U::from(0b1010_u8);
        assert_eq!(BitOps::bit_length(&value), 4);
        assert_eq!(BitOps::bit_count(&value), 2);
        assert!(BitOps::test_bit(&value, 3));
        assert_eq!(BitOps::set_bit(&value, 0), U::from(0b1011_u8));
        assert_eq!(BitOps::clear_bit(&value, 3), U::from(0b0010_u8));
        assert_eq!(BitOps::flip_bit(&value, 1), U::from(0b1000_u8));
        assert_eq!(BitOps::lowest_set_bit(&value), Some(1));
        assert_eq!(AndNot::and_not(&value, &U::from(0b0011_u8)), U::from(8_u8));
    }
}
