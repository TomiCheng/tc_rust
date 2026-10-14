//! Elliptic-curve point coordinate systems.
//!
//! Corresponds to the `COORD_*` constants on `ECCurve` in Bouncy Castle C#. The
//! coordinate system a curve uses determines how its points store coordinates
//! and which point-arithmetic formulas apply.

/// The coordinate system used to represent points on a curve.
///
/// Mirrors Bouncy Castle's `ECCurve.COORD_*` constants. `Affine` stores points
/// as `(x, y)`; the projective systems add one or more `Z` coordinates to defer
/// field inversions until a final normalization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CoordinateSystem {
    /// `(x, y)` — a point stored directly. `COORD_AFFINE`.
    Affine,
    /// Homogeneous projective `(X : Y : Z)`, `x = X/Z`, `y = Y/Z`.
    /// `COORD_HOMOGENEOUS`.
    Homogeneous,
    /// Jacobian projective `(X : Y : Z)`, `x = X/Z^2`, `y = Y/Z^3`.
    /// `COORD_JACOBIAN`.
    Jacobian,
    /// Chudnovsky Jacobian: Jacobian plus cached `Z^2`, `Z^3`.
    /// `COORD_JACOBIAN_CHUDNOVSKY`.
    JacobianChudnovsky,
    /// Modified Jacobian: Jacobian plus cached `a·Z^4`. bc's default for Fp
    /// curves. `COORD_JACOBIAN_MODIFIED`.
    JacobianModified,
    /// Lambda affine (binary-field curves). `COORD_LAMBDA_AFFINE`.
    LambdaAffine,
    /// Lambda projective (binary-field curves). `COORD_LAMBDA_PROJECTIVE`.
    LambdaProjective,
    /// Skewed (binary-field curves). `COORD_SKEWED`.
    Skewed,
}
