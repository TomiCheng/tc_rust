use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::PaddedBigUint;
use tc_modular::PaddedMontyForm;

#[derive(Clone, PartialEq, Eq)]
pub struct FpFieldElement<'a> {
    value: PaddedMontyForm<'a>,
}

impl<'a> FpFieldElement<'a> {
    pub fn new(value: PaddedMontyForm<'a>) -> Self {
        Self { value }
    }

    /// The value in `[0, q)`, at the width of `q`. Constant time.
    pub fn to_big_uint(&self) -> PaddedBigUint {
        self.value.retrieve()
    }

    /// Whether this is zero. Constant time; only the answer is revealed.
    pub fn is_zero(&self) -> bool {
        self.value == PaddedMontyForm::zero(self.value.params())
    }

    /// Whether this is one. Constant time; only the answer is revealed.
    pub fn is_one(&self) -> bool {
        self.value == PaddedMontyForm::one(self.value.params())
    }

    /// `2x`. Constant time.
    pub fn double(&self) -> Self {
        Self::new(self.value.double())
    }

    /// `x²`. Constant time.
    pub fn square(&self) -> Self {
        Self::new(self.value.square())
    }

    /// `x^e` over the full width of `e`. Constant time, for a secret exponent.
    pub fn pow(&self, exponent: &PaddedBigUint) -> Self {
        Self::new(self.value.pow(exponent))
    }

    /// `x^e`. Variable time; only for a public exponent, a secret one goes through [`pow`](Self::pow).
    pub fn pow_vartime(&self, exponent: &PaddedBigUint) -> Self {
        Self::new(self.value.pow_vartime(exponent))
    }

    /// `x⁻¹`, or `None` for zero. Constant time apart from whether there is an inverse.
    pub fn invert(&self) -> Option<Self> {
        self.value.invert().map(Self::new)
    }
}

/// `x + y`. Constant time. Panics when the fields differ.
impl<'a> Add for &FpFieldElement<'a> {
    type Output = FpFieldElement<'a>;

    fn add(self, rhs: Self) -> FpFieldElement<'a> {
        FpFieldElement::new(&self.value + &rhs.value)
    }
}

/// `x - y`. Constant time. Panics when the fields differ.
impl<'a> Sub for &FpFieldElement<'a> {
    type Output = FpFieldElement<'a>;

    fn sub(self, rhs: Self) -> FpFieldElement<'a> {
        FpFieldElement::new(&self.value - &rhs.value)
    }
}

/// `x · y`. Constant time. Panics when the fields differ.
impl<'a> Mul for &FpFieldElement<'a> {
    type Output = FpFieldElement<'a>;

    fn mul(self, rhs: Self) -> FpFieldElement<'a> {
        FpFieldElement::new(&self.value * &rhs.value)
    }
}

/// `-x`. Constant time.
impl<'a> Neg for &FpFieldElement<'a> {
    type Output = FpFieldElement<'a>;

    fn neg(self) -> FpFieldElement<'a> {
        FpFieldElement::new(-&self.value)
    }
}

/// Prints only the width, never the value, which may be secret.
impl fmt::Debug for FpFieldElement<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FpFieldElement")
            .field("limbs", &self.value.params().modulus().as_limbs().len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use tc_bigint::PaddedBigUint;

    use crate::FpField;

    fn int(value: u8) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    #[test]
    fn arithmetic_stays_below_the_prime() {
        let field = FpField::new(int(17));
        let x = field.element(&int(5));
        let y = field.element(&int(9));
        assert_eq!((&x + &y).to_big_uint(), int(14));
        assert_eq!((&x - &y).to_big_uint(), int(13));
        assert_eq!((&x * &y).to_big_uint(), int(11));
        assert_eq!((-&x).to_big_uint(), int(12));
        assert_eq!(x.double().to_big_uint(), int(10));
        assert_eq!(x.square().to_big_uint(), int(8));
    }

    #[test]
    fn an_element_times_its_inverse_is_one_and_zero_has_none() {
        let field = FpField::new(int(17));
        let x = field.element(&int(5));
        assert!((&x * &x.invert().unwrap()).is_one());
        assert!(field.element(&int(0)).invert().is_none());
    }

    #[test]
    fn both_powers_agree() {
        let field = FpField::new(int(17));
        let x = field.element(&int(3));
        assert_eq!(x.pow(&int(16)), x.pow_vartime(&int(16)));
        assert!(x.pow(&int(16)).is_one());
        assert!(field.element(&int(0)).is_zero());
    }
}
