//! Points on binary-field (F2m) short-Weierstrass curves.
//!
//! Corresponds to `F2mPoint` in Bouncy Castle C#. The curve equation over `GF(2ᵐ)`
//! is `y² + xy = x³ + ax² + b` (unlike the Fp form `y² = x³ + ax + b`), so the point
//! arithmetic formulas differ — but the data layout mirrors [`FpPoint`](super::FpPoint)
//! exactly (bc shares the same `ECPointBase` `m_curve`/`m_x`/`m_y`/`m_zs`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ec::f2m_curve::F2mCurve;
use crate::ec::f2m_field_element::F2mFieldElement;

/// A point on an [`F2mCurve`].
///
/// `coords` is `None` for the point at infinity (the group identity), otherwise
/// `Some((x, y))`. `zs` carries the projective `Z` coordinates and is empty in
/// affine coordinates. Construction and arithmetic are added later; this is the data
/// layout only.
#[derive(Clone)]
pub struct F2mPoint {
    // 回指所屬曲線（提供 a、b、體域）。
    curve: Arc<F2mCurve>,
    // 座標（bc m_x, m_y）；None = 無窮遠點。affine 時即 (x, y)，投影時為 (X, Y)。
    coords: Option<(F2mFieldElement, F2mFieldElement)>,
    // 投影 Z 座標（bc m_zs）；affine 為空 []，投影為 [Z, …]。
    zs: Vec<F2mFieldElement>,
}
