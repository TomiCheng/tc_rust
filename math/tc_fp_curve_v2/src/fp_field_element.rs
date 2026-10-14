use core::fmt;
use core::ops::{Add, Mul, Neg, Sub};

use tc_bigint::PaddedBigUint;
use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};
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

    /// A square root, or `None` for a non-residue. BC's direct formulas for
    /// `q ≡ 3 (mod 4)` and `q ≡ 5 (mod 8)`, and a Lucas sequence for
    /// `q ≡ 1 (mod 8)`. Variable time; only for public values.
    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() || self.is_one() {
            return Some(self.clone());
        }
        let q = self.value.params().modulus();
        if q.bit(1) {
            return self.check_sqrt(self.pow_vartime(&((q >> 2) + 1u32)));
        }
        if q.bit(2) {
            let t1 = self.pow_vartime(&(q >> 3));
            let t2 = &t1 * self;
            if (&t2 * &t1).is_one() {
                return self.check_sqrt(t2);
            }
            let t4 = self
                .sibling(&PaddedBigUint::from(2u8))
                .pow_vartime(&(q >> 2));
            return self.check_sqrt(&t2 * &t4);
        }

        let legendre = q >> 1;
        if !self.pow_vartime(&legendre).is_one() {
            return None;
        }
        let four_x = self.double().double();
        let k = &legendre + 1u32;
        let minus_one = -&self.sibling(&PaddedBigUint::from(1u8));
        let mut p_value = PaddedBigUint::from(1u8);
        loop {
            if &p_value >= q {
                return None;
            }
            let p = self.sibling(&p_value);
            let discriminant = &p.square() - &four_x;
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
            ql = &ql * &qh;
            if k.bit(j) {
                qh = &ql * self;
                uh = &uh * &vh;
                vl = &(&vh * &vl) - &(p * &ql);
                vh = &vh.square() - &qh.double();
            } else {
                qh = ql.clone();
                uh = &(&uh * &vl) - &ql;
                vh = &(&vh * &vl) - &(p * &ql);
                vl = &vl.square() - &ql.double();
            }
            j -= 1;
        }

        ql = &ql * &qh;
        qh = &ql * self;
        uh = &(&uh * &vl) - &ql;
        vl = &(&vh * &vl) - &(p * &ql);
        ql = &ql * &qh;

        for _ in 0..s {
            uh = &uh * &vl;
            vl = &vl.square() - &ql.double();
            ql = ql.square();
        }
        (uh, vl)
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

    #[test]
    fn square_roots_exist_exactly_for_the_squares_in_every_branch() {
        for q in [11u8, 13, 17, 41, 73, 97, 113] {
            let field = FpField::new(int(q));
            for value in 0..q {
                let x = field.element(&int(value));
                let is_square = (0..q).any(|r| field.element(&int(r)).square() == x);
                match x.sqrt() {
                    Some(root) => assert_eq!(root.square(), x, "q = {q}, x = {value}"),
                    None => assert!(!is_square, "q = {q}, x = {value}"),
                }
                assert_eq!(x.sqrt().is_some(), is_square, "q = {q}, x = {value}");
            }
        }
    }
}
