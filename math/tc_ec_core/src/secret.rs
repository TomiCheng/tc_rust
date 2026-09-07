//! Fixed-window multiplication with complete masked exceptional-case handling.
//! Inputs are public points and fixed-length little-endian secret scalar bytes.
//! Ordinary `Point` operations are used only when importing public inputs or
//! explicitly revealing a result. Secret intermediates never use wNAF.

use crate::{AlgorithmError, Curve, FieldElement, Point};
use alloc::{sync::Arc, vec::Vec};
pub use tc_constant_time::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Field operations with fixed schedules for secret values. Domain parameters
/// and storage sizes are public. Inversion must map zero to zero without failing.
pub trait SecretField: FieldElement + ConditionallySelectable + ConstantTimeEq {
    /// Zero in this public field domain.
    fn ct_zero(&self) -> Self;
    /// One in this public field domain.
    fn ct_one(&self) -> Self;
    /// Fixed-schedule field addition.
    fn ct_add(&self, rhs: &Self) -> Self;
    /// Fixed-schedule field subtraction.
    fn ct_sub(&self, rhs: &Self) -> Self;
    /// Fixed-schedule field multiplication.
    fn ct_mul(&self, rhs: &Self) -> Self;
    /// Fixed-schedule field square.
    fn ct_square(&self) -> Self {
        self.ct_mul(self)
    }
    /// Fixed-schedule inverse; zero maps to zero.
    fn ct_invert(&self) -> Self;
}

/// A curve with a secret-capable field backend.
pub trait SecretCurve: Curve {
    /// Selects binary homogeneous formulas instead of prime Jacobian formulas.
    const BINARY: bool;

    /// 回傳體域的有效位元數，供 shared secret 產生定長編碼。
    fn field_size(&self) -> usize;

    /// 將公開的體元素位元表示轉成曲線的純量整數型別。
    ///
    /// ECDSA 會用這個入口把正規化後的 affine X 座標轉成整數；若純量型別
    /// 無法容納完整座標，回傳 `None`。
    fn field_element_to_scalar(value: &Self::Field) -> Option<Self::Scalar>;
}

/// A point whose coordinates may be secret. It deliberately has no Debug or Eq.
/// Use `reveal` only when the result is ready to become public.
pub struct SecretPoint<C: SecretCurve>
where
    C::Field: SecretField,
{
    curve: Arc<C>,
    x: C::Field,
    y: C::Field,
    z: C::Field,
}
impl<C: SecretCurve> Clone for SecretPoint<C>
where
    C::Field: SecretField,
{
    fn clone(&self) -> Self {
        Self {
            curve: self.curve.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
        }
    }
}
impl<C: SecretCurve> ConditionallySelectable for SecretPoint<C>
where
    C::Field: SecretField,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        // Internal callers use one public curve; no secret coordinate inspection.
        assert!(a.curve.a() == b.curve.a() && a.curve.b() == b.curve.b());
        Self {
            curve: a.curve.clone(),
            x: C::Field::conditional_select(&a.x, &b.x, choice),
            y: C::Field::conditional_select(&a.y, &b.y, choice),
            z: C::Field::conditional_select(&a.z, &b.z, choice),
        }
    }
}
impl<C: SecretCurve> SecretPoint<C>
where
    C::Field: SecretField,
{
    fn identity(curve: &Arc<C>) -> Self {
        Self {
            curve: curve.clone(),
            x: curve.a().ct_zero(),
            y: curve.a().ct_one(),
            z: curve.a().ct_zero(),
        }
    }

    /// Validates and imports a public point. This preparation is variable time.
    pub fn from_public(point: &C::Point) -> Result<Self, AlgorithmError> {
        crate::validate_point(point)?;
        let curve = point.curve().clone();
        if point.is_identity() {
            return Ok(Self::identity(&curve));
        }
        let point = point.normalize();
        Ok(Self {
            x: point.x().unwrap(),
            y: point.y().unwrap(),
            z: curve.a().ct_one(),
            curve,
        })
    }

    /// Declassifies the result and constructs an ordinary point. Variable time.
    pub fn reveal(&self) -> C::Point {
        if self.is_identity().unwrap_u8() == 1 {
            return self.curve.identity();
        }
        let inverse = self.z.ct_invert();
        let (x, y) = if C::BINARY {
            (self.x.ct_mul(&inverse), self.y.ct_mul(&inverse))
        } else {
            let i2 = inverse.ct_square();
            (self.x.ct_mul(&i2), self.y.ct_mul(&i2.ct_mul(&inverse)))
        };
        self.curve.create_point(x, y)
    }

    /// Tests identity without revealing the result.
    pub fn is_identity(&self) -> Choice {
        self.z.ct_eq(&self.z.ct_zero())
    }

    /// Doubles with a fixed field-operation schedule, including identity/torsion.
    pub fn double(&self) -> Self {
        let (x, y, z) = (&self.x, &self.y, &self.z);
        let (nx, ny, nz) = if C::BINARY {
            let xz = x.ct_mul(z);
            let yz = y.ct_mul(z);
            let x2 = x.ct_square();
            let s = x2.ct_add(&yz);
            let v = xz.ct_square();
            let h = s
                .ct_square()
                .ct_add(&s.ct_mul(&xz))
                .ct_add(&self.curve.a().ct_mul(&v));
            let nx = xz.ct_mul(&h);
            let ny = x2.ct_square().ct_mul(&xz).ct_add(&h.ct_mul(&s.ct_add(&xz)));
            (nx, ny, xz.ct_mul(&v))
        } else {
            let xx = x.ct_square();
            let yy = y.ct_square();
            let yyyy = yy.ct_square();
            let s = x.ct_mul(&yy);
            let s = s.ct_add(&s);
            let s = s.ct_add(&s);
            let m = xx
                .ct_add(&xx)
                .ct_add(&xx)
                .ct_add(&self.curve.a().ct_mul(&z.ct_square().ct_square()));
            let nx = m.ct_square().ct_sub(&s.ct_add(&s));
            let eight = yyyy.ct_add(&yyyy);
            let eight = eight.ct_add(&eight);
            let eight = eight.ct_add(&eight);
            let ny = m.ct_mul(&s.ct_sub(&nx)).ct_sub(&eight);
            let nz = y.ct_mul(z);
            (nx, ny, nz.ct_add(&nz))
        };
        let candidate = Self {
            curve: self.curve.clone(),
            x: nx,
            y: ny,
            z: nz,
        };
        Self::conditional_select(
            &candidate,
            &Self::identity(&self.curve),
            candidate.is_identity(),
        )
    }

    /// Adds with a fixed schedule, masking equal, opposite and identity cases.
    pub fn add(&self, rhs: &Self) -> Self {
        let (nx, ny, nz, h, r) = if C::BINARY {
            let u = rhs.y.ct_mul(&self.z).ct_add(&self.y.ct_mul(&rhs.z));
            let v = rhs.x.ct_mul(&self.z).ct_add(&self.x.ct_mul(&rhs.z));
            let v2 = v.ct_square();
            let v3 = v2.ct_mul(&v);
            let w = self.z.ct_mul(&rhs.z);
            let uv = u.ct_add(&v);
            let a = uv
                .ct_mul(&u)
                .ct_add(&v2.ct_mul(self.curve.a()))
                .ct_mul(&w)
                .ct_add(&v3);
            let nx = v.ct_mul(&a);
            let ny = u
                .ct_mul(&self.x)
                .ct_add(&v.ct_mul(&self.y))
                .ct_mul(&v2.ct_mul(&rhs.z))
                .ct_add(&uv.ct_mul(&a));
            (nx, ny, v3.ct_mul(&w), v, u)
        } else {
            let z1s = self.z.ct_square();
            let z2s = rhs.z.ct_square();
            let u1 = self.x.ct_mul(&z2s);
            let u2 = rhs.x.ct_mul(&z1s);
            let s1 = self.y.ct_mul(&z2s.ct_mul(&rhs.z));
            let s2 = rhs.y.ct_mul(&z1s.ct_mul(&self.z));
            let h = u2.ct_sub(&u1);
            let r = s2.ct_sub(&s1);
            let h2 = h.ct_square();
            let h3 = h.ct_mul(&h2);
            let u = u1.ct_mul(&h2);
            let nx = r.ct_square().ct_sub(&h3).ct_sub(&u.ct_add(&u));
            let ny = r.ct_mul(&u.ct_sub(&nx)).ct_sub(&s1.ct_mul(&h3));
            (nx, ny, h.ct_mul(&self.z).ct_mul(&rhs.z), h, r)
        };
        let candidate = Self {
            curve: self.curve.clone(),
            x: nx,
            y: ny,
            z: nz,
        };
        let zero_h = h.ct_eq(&h.ct_zero());
        let zero_r = r.ct_eq(&r.ct_zero());
        let mut result = Self::conditional_select(&candidate, &Self::identity(&self.curve), zero_h);
        result = Self::conditional_select(&result, &self.double(), zero_h & zero_r);
        result = Self::conditional_select(&result, rhs, self.is_identity());
        Self::conditional_select(&result, self, rhs.is_identity())
    }
}

impl<C: SecretCurve> ConstantTimeEq for SecretPoint<C>
where
    C::Field: SecretField,
{
    fn ct_eq(&self, rhs: &Self) -> Choice {
        assert!(self.curve.a() == rhs.curve.a() && self.curve.b() == rhs.curve.b());
        let (x1, x2, y1, y2) = if C::BINARY {
            (
                self.x.ct_mul(&rhs.z),
                rhs.x.ct_mul(&self.z),
                self.y.ct_mul(&rhs.z),
                rhs.y.ct_mul(&self.z),
            )
        } else {
            let z1 = self.z.ct_square();
            let z2 = rhs.z.ct_square();
            (
                self.x.ct_mul(&z2),
                rhs.x.ct_mul(&z1),
                self.y.ct_mul(&z2.ct_mul(&rhs.z)),
                rhs.y.ct_mul(&z1.ct_mul(&self.z)),
            )
        };
        let i1 = self.is_identity();
        let i2 = rhs.is_identity();
        (i1 & i2) | (!i1 & !i2 & x1.ct_eq(&x2) & y1.ct_eq(&y2))
    }
}

/// A full-scan table for secret indices. Every lookup touches every entry.
pub struct ECLookupTable<C: SecretCurve>
where
    C::Field: SecretField,
{
    points: Vec<SecretPoint<C>>,
}
impl<C: SecretCurve> ECLookupTable<C>
where
    C::Field: SecretField,
{
    /// Imports a nonempty slice of public points from equivalent curves.
    pub fn new(points: &[C::Point]) -> Result<Self, AlgorithmError> {
        let first = points.first().ok_or(AlgorithmError::InvalidLength)?;
        let mut table = Vec::with_capacity(points.len());
        for point in points {
            table.push(SecretPoint::from_public(&crate::import_point(
                first.curve(),
                point,
            )?)?);
        }
        Ok(Self { points: table })
    }
    /// Returns the selected point, or identity for an out-of-range secret index.
    pub fn lookup(&self, index: usize) -> SecretPoint<C> {
        let mut result = SecretPoint::identity(&self.points[0].curve);
        for (i, point) in self.points.iter().enumerate() {
            result = SecretPoint::conditional_select(&result, point, i.ct_eq(&index));
        }
        result
    }
}

/// Fixed-window multiplication. Scalar byte length is public; leading zeros
/// are processed. All bits are consumed, without reduction or truncation.
pub fn multiply_secret<C: SecretCurve>(
    point: &C::Point,
    scalar_le: &[u8],
) -> Result<SecretPoint<C>, AlgorithmError>
where
    C::Field: SecretField,
{
    let p = SecretPoint::from_public(point)?;
    let mut points = Vec::with_capacity(16);
    points.push(SecretPoint::identity(&p.curve));
    for i in 1..16 {
        points.push(points[i - 1].add(&p));
    }
    let table = ECLookupTable { points };
    let mut result = SecretPoint::identity(&p.curve);
    for byte in scalar_le.iter().rev() {
        for shift in [4, 0] {
            for _ in 0..4 {
                result = result.double();
            }
            result = result.add(&table.lookup(((byte >> shift) & 15) as usize));
        }
    }
    Ok(result)
}

/// Adds two secret scalar multiples. Lengths and input points are public.
pub fn sum_of_two_multiplies_secret<C: SecretCurve>(
    p: &C::Point,
    a_le: &[u8],
    q: &C::Point,
    b_le: &[u8],
) -> Result<SecretPoint<C>, AlgorithmError>
where
    C::Field: SecretField,
{
    let q = crate::import_point(p.curve(), q)?;
    Ok(multiply_secret::<C>(p, a_le)?.add(&multiply_secret::<C>(&q, b_le)?))
}
