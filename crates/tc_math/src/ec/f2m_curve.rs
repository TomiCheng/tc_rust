//! Binary-field (F2m) short-Weierstrass curves.
//!
//! Corresponds to `F2mCurve` in Bouncy Castle C#. The curve `y² + xy = x³ + ax² + b`
//! lives over `GF(2ᵐ)`; it owns the shared [`F2mField`] definition (as an `Arc`, so
//! its coefficients and every point share one copy) plus the coefficients `a`, `b`.
//!
//! Mirrors [`FpCurve`](super::FpCurve): the same shape, but the field is an
//! `Arc<F2mField>` instead of the prime modulus `q` and residue `r`.

use alloc::sync::Arc;

use crate::big_integer::BigInteger;
use crate::ec::coordinate_system::CoordinateSystem;
use crate::ec::f2m_field::F2mField;
use crate::ec::f2m_field_element::F2mFieldElement;

/// A short-Weierstrass elliptic curve `y² + xy = x³ + ax² + b` over `GF(2ᵐ)`.
///
/// Mirrors bc `F2mCurve`. Construction and point operations are added later; this is
/// the data layout only.
pub struct F2mCurve {
    // 共享體域定義（取代 FpCurve 的 q + r）。a/b 與 point 都 clone 這個 Arc。
    field: Arc<F2mField>,
    // Weierstrass 係數 a、b（體域元素，與 field 同源）。
    a: F2mFieldElement,
    b: F2mFieldElement,
    // 群階與 cofactor（未必已知）。
    order: Option<BigInteger>,
    cofactor: Option<BigInteger>,
    // 點座標系。bc F2m 預設 COORD_LAMBDA_PROJECTIVE；MVP 比照 FpCurve 先走 Affine。
    coordinate_system: CoordinateSystem,
}
