//! Prime-field elliptic curves.
//!
//! Corresponds to `FpCurve` in Bouncy Castle C# — a short-Weierstrass curve
//! `y^2 = x^3 + ax + b` over the prime field GF(q). Points ([`FpPoint`]) hold an
//! `Arc<FpCurve>` back-reference and are created through the curve.
//!
//! [`FpPoint`]: crate::ec::fp_point::FpPoint

use crate::big_integer::BigInteger;
use crate::ec::CoordinateSystem;
use crate::ec::fp_field_element::FpFieldElement;

/// A short-Weierstrass elliptic curve `y^2 = x^3 + ax + b` over GF(q).
///
/// Mirrors `FpCurve`. Holds the field modulus `q` and its reduction residue
/// `r` (computed once and shared with every field element the curve creates),
/// the coefficients `a`, `b`, and the optional group `order` and `cofactor`.
pub struct FpCurve {
    // 體域質數（模數）。
    q: BigInteger,
    // 快速模約簡殘值，算一次、分給每個由本曲線建立的體域元素。
    r: Option<BigInteger>,
    // 曲線係數 a、b（體域元素）。
    a: FpFieldElement,
    b: FpFieldElement,
    // 群階與 cofactor（未必已知）。
    order: Option<BigInteger>,
    cofactor: Option<BigInteger>,
    // 點的座標系。MVP 只支援 Affine（bc 預設是 JacobianModified，等實作 Jacobian
    // 再改預設）。
    coordinate_system: CoordinateSystem,
}

impl FpCurve {
    /// Creates the curve `y^2 = x^3 + ax + b` over GF(`q`).
    ///
    /// `a` and `b` are validated to lie in `[0, q)`.
    ///
    /// # Panics
    ///
    /// Panics if `q` is not positive, or if `a`/`b` are out of range.
    pub fn new(
        q: BigInteger,
        a: BigInteger,
        b: BigInteger,
        order: Option<BigInteger>,
        cofactor: Option<BigInteger>,
    ) -> Self {
        assert!(q.sign() > 0, "field modulus q must be positive");
        // 殘值算一次，之後所有體域元素共用（對應 bc AbstractFpCurve 的 m_r）。
        let r = FpFieldElement::calculate_residue(&q);
        let a = Self::make_field_element(&q, a, &r);
        let b = Self::make_field_element(&q, b, &r);
        FpCurve {
            q,
            r,
            a,
            b,
            order,
            cofactor,
            coordinate_system: CoordinateSystem::Affine,
        }
    }

    /// Builds a field element for this curve's field from an integer,
    /// validating `0 <= x < q`.
    ///
    /// Corresponds to `FromBigInteger` in Bouncy Castle.
    ///
    /// # Panics
    ///
    /// Panics if `x` is negative or `>= q`.
    pub fn field_element(&self, x: BigInteger) -> FpFieldElement {
        Self::make_field_element(&self.q, x, &self.r)
    }

    // 共用的建元素邏輯：範圍檢查 + 以共用的 r 建立（bc FromBigInteger 的檢查）。
    fn make_field_element(q: &BigInteger, x: BigInteger, r: &Option<BigInteger>) -> FpFieldElement {
        assert!(
            x.sign() >= 0 && &x < q,
            "value invalid for Fp field element"
        );
        FpFieldElement::new(q.clone(), x, r.clone())
    }

    /// Returns the field modulus `q`.
    pub fn q(&self) -> &BigInteger {
        &self.q
    }

    /// Returns the curve coefficient `a`.
    pub fn a(&self) -> &FpFieldElement {
        &self.a
    }

    /// Returns the curve coefficient `b`.
    pub fn b(&self) -> &FpFieldElement {
        &self.b
    }

    /// Returns the group order `n`, if known.
    pub fn order(&self) -> Option<&BigInteger> {
        self.order.as_ref()
    }

    /// Returns the cofactor `h`, if known.
    pub fn cofactor(&self) -> Option<&BigInteger> {
        self.cofactor.as_ref()
    }

    /// Returns the coordinate system points on this curve use.
    ///
    /// Corresponds to `CoordinateSystem` in Bouncy Castle.
    pub fn coordinate_system(&self) -> CoordinateSystem {
        self.coordinate_system
    }

    /// Returns this curve configured to use `coordinate_system` for its points.
    ///
    /// Corresponds to `Configure().SetCoordinateSystem(...)` in Bouncy Castle.
    /// Note: only [`CoordinateSystem::Affine`] point arithmetic is implemented
    /// so far; other systems will be added later.
    pub fn with_coordinate_system(mut self, coordinate_system: CoordinateSystem) -> Self {
        self.coordinate_system = coordinate_system;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // secp256k1: y^2 = x^3 + 7 over GF(p).
    fn secp256k1() -> FpCurve {
        let p = BigInteger::from_str_radix(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap();
        FpCurve::new(
            p,
            BigInteger::from_u32(0),
            BigInteger::from_u32(7),
            None,
            None,
        )
    }

    #[test]
    fn new_sets_coefficients() {
        let c = secp256k1();
        assert!(c.a().is_zero());
        assert_eq!(c.b().as_ref(), &BigInteger::from_u32(7));
        assert_eq!(c.coordinate_system(), CoordinateSystem::Affine);
    }

    #[test]
    fn with_coordinate_system_overrides_default() {
        let c = secp256k1().with_coordinate_system(CoordinateSystem::JacobianModified);
        assert_eq!(c.coordinate_system(), CoordinateSystem::JacobianModified);
    }

    #[test]
    fn field_element_builds_element() {
        let c = secp256k1();
        let e = c.field_element(BigInteger::from_u32(5));
        assert_eq!(e.as_ref(), &BigInteger::from_u32(5));
    }

    #[test]
    #[should_panic(expected = "value invalid")]
    fn field_element_rejects_out_of_range() {
        let c = secp256k1();
        c.field_element(c.q().clone()); // x == q 越界
    }
}
