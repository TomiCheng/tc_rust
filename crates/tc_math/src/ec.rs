//! Elliptic curve mathematics.
//!
//! Ported from Bouncy Castle C# `Org.BouncyCastle.Math.EC`. The initial scope is
//! prime-field (Fp) short-Weierstrass curves; binary fields (F2m) and the
//! Montgomery/Edwards curves are planned for later stages.

pub mod coordinate_system;
pub mod f2m_curve;
mod f2m_field;
pub mod f2m_field_element;
pub mod f2m_point;
pub mod fp_curve;
pub mod fp_field_element;
pub mod fp_point;
pub mod point_codec;

pub use coordinate_system::CoordinateSystem;
pub use f2m_curve::F2mCurve;
pub use f2m_field_element::F2mFieldElement;
pub use f2m_point::F2mPoint;
pub use fp_curve::FpCurve;
pub use fp_field_element::FpFieldElement;
pub use fp_point::FpPoint;
pub use point_codec::PointDecodeError;
