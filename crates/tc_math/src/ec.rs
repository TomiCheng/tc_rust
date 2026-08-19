//! Elliptic curve mathematics.
//!
//! Ported from Bouncy Castle C# `Org.BouncyCastle.Math.EC`. The initial scope is
//! prime-field (Fp) short-Weierstrass curves; binary fields (F2m) and the
//! Montgomery/Edwards curves are planned for later stages.

pub mod fp_curve;
pub mod fp_field_element;
pub mod fp_point;

pub use fp_curve::FpCurve;
pub use fp_field_element::FpFieldElement;
pub use fp_point::FpPoint;
