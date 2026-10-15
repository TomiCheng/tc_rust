use core::fmt;

use tc_bigint::PaddedBigUint;
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
use tc_ec_core_v2::{FieldElement, PrimeFieldElement};
use tc_modular::PaddedMontyForm;
use tc_zeroize::Zeroize;

#[derive(Clone, PartialEq, Eq)]
pub struct FpFieldElement<'a> {
    value: PaddedMontyForm<'a>,
}

impl<'a> FpFieldElement<'a> {
    pub fn new(value: PaddedMontyForm<'a>) -> Self {
        Self { value }
    }

    /// `2x`. Constant time.
    pub fn double(&self) -> Self {
        Self::new(self.value.double())
    }

    /// `x^e` over the full width of `e`. Constant time, for a secret exponent.
    pub fn pow(&self, exponent: &PaddedBigUint) -> Self {
        Self::new(self.value.pow(exponent))
    }

    /// `x^e`. Variable time; only for a public exponent, a secret one goes through [`pow`](Self::pow).
    pub fn pow_vartime(&self, exponent: &PaddedBigUint) -> Self {
        Self::new(self.value.pow_vartime(exponent))
    }

    fn sibling(&self, value: &PaddedBigUint) -> Self {
        Self::new(PaddedMontyForm::new(value, self.value.params()))
    }

    fn check_sqrt(&self, candidate: Self) -> Option<Self> {
        (candidate.square() == *self).then_some(candidate)
    }

    fn mod_half_abs(&self, value: &Self) -> Self {
        let value = value.to_big_uint();
        let half = if value.bit(0) {
            (self.value.params().modulus() - &value) >> 1
        } else {
            value >> 1
        };
        self.sibling(&half)
    }

    fn lucas_sequence(&self, p: &Self, k: &PaddedBigUint) -> (Self, Self) {
        let n = k.bits();
        let s = k.trailing_zeros().expect("k is not zero");
        let one = self.sibling(&PaddedBigUint::from(1u8));
        let mut uh = one.clone();
        let mut vl = one.double();
        let mut vh = p.clone();
        let mut ql = one.clone();
        let mut qh = one;

        let mut j = n - 1;
        while j > s {
            ql = ql.multiply(&qh);
            if k.bit(j) {
                qh = ql.multiply(self);
                uh = uh.multiply(&vh);
                vl = vh.multiply(&vl).subtract(&p.multiply(&ql));
                vh = vh.square().subtract(&qh.double());
            } else {
                qh = ql.clone();
                uh = uh.multiply(&vl).subtract(&ql);
                vh = vh.multiply(&vl).subtract(&p.multiply(&ql));
                vl = vl.square().subtract(&ql.double());
            }
            j -= 1;
        }

        ql = ql.multiply(&qh);
        qh = ql.multiply(self);
        uh = uh.multiply(&vl).subtract(&ql);
        vl = vh.multiply(&vl).subtract(&p.multiply(&ql));
        ql = ql.multiply(&qh);

        for _ in 0..s {
            uh = uh.multiply(&vl);
            vl = vl.square().subtract(&ql.double());
            ql = ql.square();
        }
        (uh, vl)
    }
}

/// `a` or `b`, as the choice says. Constant time. Panics when the fields differ.
impl ConditionallySelectable for FpFieldElement<'_> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(PaddedMontyForm::conditional_select(
            &a.value, &b.value, choice,
        ))
    }
}

/// Constant time.
impl ConstantTimeEq for FpFieldElement<'_> {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.value.ct_eq(&rhs.value)
    }
}

/// Wipes the value, which may be secret, so that it does not stay in freed memory; this
/// covers every temporary of the point formulas and every coordinate. Constant time.
impl Drop for FpFieldElement<'_> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Constant time apart from `sqrt`.
impl FieldElement for FpFieldElement<'_> {
    /// Whether this is zero. Constant time; only the answer is revealed.
    fn is_zero(&self) -> bool {
        self.value == PaddedMontyForm::zero(self.value.params())
    }

    /// Whether this is one. Constant time; only the answer is revealed.
    fn is_one(&self) -> bool {
        self.value == PaddedMontyForm::one(self.value.params())
    }

    /// `x + y`. Constant time. Panics when the fields differ.
    fn add(&self, rhs: &Self) -> Self {
        Self::new(&self.value + &rhs.value)
    }

    /// `x - y`. Constant time. Panics when the fields differ.
    fn subtract(&self, rhs: &Self) -> Self {
        Self::new(&self.value - &rhs.value)
    }

    /// `x · y`. Constant time. Panics when the fields differ.
    fn multiply(&self, rhs: &Self) -> Self {
        Self::new(&self.value * &rhs.value)
    }

    /// `x²`. Constant time.
    fn square(&self) -> Self {
        Self::new(self.value.square())
    }

    /// A square root, or `None` for a non-residue. BC's direct formulas for
    /// `q ≡ 3 (mod 4)` and `q ≡ 5 (mod 8)`, and a Lucas sequence for
    /// `q ≡ 1 (mod 8)`. Variable time; only for public values.
    fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(self.clone());
        }
        let q = self.value.params().modulus();
        if q.bit(1) {
            return self.check_sqrt(self.pow_vartime(&((q >> 2) + 1u32)));
        }
        if q.bit(2) {
            let t1 = self.pow_vartime(&(q >> 3));
            let t2 = t1.multiply(self);
            if t2.multiply(&t1).is_one() {
                return self.check_sqrt(t2);
            }
            let t4 = self
                .sibling(&PaddedBigUint::from(2u8))
                .pow_vartime(&(q >> 2));
            return self.check_sqrt(t2.multiply(&t4));
        }

        let legendre = q >> 1;
        if !self.pow_vartime(&legendre).is_one() {
            return None;
        }
        let four_x = self.double().double();
        let k = &legendre + 1u32;
        let minus_one = self.sibling(&PaddedBigUint::from(1u8)).negate();
        let mut p_value = PaddedBigUint::from(1u8);
        loop {
            if &p_value >= q {
                return None;
            }
            let p = self.sibling(&p_value);
            let discriminant = p.square().subtract(&four_x);
            if discriminant.pow_vartime(&legendre) == minus_one {
                let (u, v) = self.lucas_sequence(&p, &k);
                if v.square() == four_x {
                    return Some(self.mod_half_abs(&v));
                }
                if !u.is_one() && u != minus_one {
                    return None;
                }
            }
            p_value += 1u32;
        }
    }

    /// `-x`. Constant time.
    fn negate(&self) -> Self {
        Self::new(-&self.value)
    }

    /// `x⁻¹`, or `None` for zero. Constant time apart from whether there is an inverse.
    fn invert(&self) -> Option<Self> {
        self.value.invert().map(Self::new)
    }
}

impl PrimeFieldElement for FpFieldElement<'_> {
    type BigUint = PaddedBigUint;

    /// An element of the same field; a value of `q` or more is reduced. Constant time.
    fn element_from_big_uint(&self, value: &PaddedBigUint) -> Self {
        self.sibling(value)
    }

    /// The value in `[0, q)`, at the width of `q`. Constant time.
    fn to_big_uint(&self) -> PaddedBigUint {
        self.value.retrieve()
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
    use tc_ec_core_v2::{FieldElement, PrimeFieldElement};

    use crate::FpField;

    fn int(value: u8) -> PaddedBigUint {
        PaddedBigUint::from(value)
    }

    #[test]
    fn arithmetic_stays_below_the_prime() {
        let field = FpField::new(int(17)).unwrap();
        let x = field.element(&int(5)).unwrap();
        let y = field.element(&int(9)).unwrap();
        assert_eq!(x.add(&y).to_big_uint(), int(14));
        assert_eq!(x.subtract(&y).to_big_uint(), int(13));
        assert_eq!(x.multiply(&y).to_big_uint(), int(11));
        assert_eq!(x.negate().to_big_uint(), int(12));
        assert_eq!(x.double().to_big_uint(), int(10));
        assert_eq!(x.square().to_big_uint(), int(8));
    }

    #[test]
    fn an_element_times_its_inverse_is_one_and_zero_has_none() {
        let field = FpField::new(int(17)).unwrap();
        let x = field.element(&int(5)).unwrap();
        assert!(x.multiply(&x.invert().unwrap()).is_one());
        assert!(field.element(&int(0)).unwrap().invert().is_none());
    }

    #[test]
    fn integers_round_trip_through_the_field_and_larger_ones_are_reduced() {
        let field = FpField::new(int(17)).unwrap();
        let x = field.element(&int(5)).unwrap();
        for value in 0..17 {
            assert_eq!(
                x.element_from_big_uint(&int(value)).to_big_uint(),
                int(value)
            );
        }
        assert_eq!(x.element_from_big_uint(&int(20)).to_big_uint(), int(3));
        assert_eq!(x.to_big_uint().as_limbs().len(), int(17).as_limbs().len());
    }

    #[test]
    fn both_powers_agree() {
        let field = FpField::new(int(17)).unwrap();
        let x = field.element(&int(3)).unwrap();
        assert_eq!(x.pow(&int(16)), x.pow_vartime(&int(16)));
        assert!(x.pow(&int(16)).is_one());
        assert!(field.element(&int(0)).unwrap().is_zero());
    }

    #[test]
    fn square_roots_exist_exactly_for_the_squares_in_every_branch() {
        for q in [11u8, 13, 17, 41, 73, 97, 113] {
            let field = FpField::new(int(q)).unwrap();
            for value in 0..q {
                let x = field.element(&int(value)).unwrap();
                let is_square = (0..q).any(|r| field.element(&int(r)).unwrap().square() == x);
                match x.sqrt() {
                    Some(root) => assert_eq!(root.square(), x, "q = {q}, x = {value}"),
                    None => assert!(!is_square, "q = {q}, x = {value}"),
                }
                assert_eq!(x.sqrt().is_some(), is_square, "q = {q}, x = {value}");
            }
        }
    }
}
