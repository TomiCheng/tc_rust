use crate::SecTVarPoint;
use crate::sect_element::SecTElement;
use core::fmt;
use tc_bigint::PaddedBigUint;
use tc_ec_core_v2::{CoordinateSystem, Curve};

/// A SEC binary curve over the field of `F`, in lambda-projective coordinates as BC's
/// `SecT*Curve`s are; variable time, only for public values.
pub struct SecTVarCurve<F> {
    a: F,
    b: F,
    order: PaddedBigUint,
    cofactor: PaddedBigUint,
    small_b: bool,
}

impl<F: SecTElement> SecTVarCurve<F> {
    pub(crate) fn new(a: F, b: F, order: PaddedBigUint, cofactor: PaddedBigUint) -> Self {
        let small_b = bit_length(&b) < F::M / 2;
        Self {
            a,
            b,
            order,
            cofactor,
            small_b,
        }
    }

    // Whether b has fewer bits than half the field, which picks BC's doubling formula.
    pub(crate) fn small_b(&self) -> bool {
        self.small_b
    }
}

fn bit_length<F: SecTElement>(x: &F) -> usize {
    let mut bytes = [0; 72];
    let bytes = &mut bytes[..x.encoded_length()];
    x.encode_to(bytes);
    match bytes.iter().position(|&byte| byte != 0) {
        Some(i) => (bytes.len() - i) * 8 - bytes[i].leading_zeros() as usize,
        None => 0,
    }
}

impl<'a, F: SecTElement> Curve for &'a SecTVarCurve<F> {
    type Field = F;
    type Point = SecTVarPoint<'a, F>;
    type Scalar = PaddedBigUint;

    fn a(&self) -> &F {
        &self.a
    }

    fn b(&self) -> &F {
        &self.b
    }

    fn order(&self) -> Option<&PaddedBigUint> {
        Some(&self.order)
    }

    fn cofactor(&self) -> Option<&PaddedBigUint> {
        Some(&self.cofactor)
    }

    fn zero(&self) -> F {
        F::zero()
    }

    fn one(&self) -> F {
        F::one()
    }

    fn infinity(&self) -> SecTVarPoint<'a, F> {
        SecTVarPoint::infinity(self)
    }

    fn create_point(&self, x: F, y: F) -> SecTVarPoint<'a, F> {
        SecTVarPoint::new(self, x, y)
    }

    fn coordinate_system(&self) -> CoordinateSystem {
        CoordinateSystem::LambdaProjective
    }

    /// wNAF. Variable time; only for public scalars.
    fn multiply(point: &SecTVarPoint<'a, F>, scalar: &PaddedBigUint) -> SecTVarPoint<'a, F> {
        tc_ec_core_v2::wnaf::wnaf_mul_point::<Self>(point, scalar)
    }
}

/// The same coefficients, as in BC; the order and cofactor are left out.
impl<F: SecTElement> PartialEq for SecTVarCurve<F> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b
    }
}

impl<F: SecTElement> Eq for SecTVarCurve<F> {}

impl<F> fmt::Debug for SecTVarCurve<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecTVarCurve").finish_non_exhaustive()
    }
}
