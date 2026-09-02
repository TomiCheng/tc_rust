//! Shared SEC point-encoding codec types for elliptic curves.
//!
//! The point encoding format (X9.62 / SEC 1) is field-agnostic: prime-field and
//! binary-field curves share the same encoding types and error cases, differing
//! only in the decompression step. This module holds the shared pieces —
//! currently the decode error type.

/// An error decoding a point from its SEC encoding.
///
/// Returned by the curves' `decode_point`. The variants correspond to the
/// distinct failure cases Bouncy Castle raises as exceptions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PointDecodeError {
    /// The input was empty (no encoding-type prefix byte).
    Empty,
    /// The byte length does not match the encoding type.
    InvalidLength,
    /// The leading encoding-type byte is not a recognized value.
    UnknownEncoding(u8),
    /// A coordinate value is not in the field range `[0, q)`.
    CoordinateOutOfRange,
    /// A hybrid encoding's y-parity prefix disagrees with the Y coordinate.
    InconsistentHybridY,
    /// The decoded coordinates do not lie on the curve (or a compressed x is
    /// not a valid x-coordinate).
    NotOnCurve,
}

impl core::fmt::Display for PointDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PointDecodeError::Empty => write!(f, "empty point encoding"),
            PointDecodeError::InvalidLength => write!(f, "incorrect length for point encoding"),
            PointDecodeError::UnknownEncoding(b) => {
                write!(f, "unknown point encoding type 0x{b:02x}")
            }
            PointDecodeError::CoordinateOutOfRange => {
                write!(f, "coordinate value out of field range")
            }
            PointDecodeError::InconsistentHybridY => {
                write!(f, "inconsistent Y coordinate in hybrid point encoding")
            }
            PointDecodeError::NotOnCurve => write!(f, "point is not on the curve"),
        }
    }
}

impl core::error::Error for PointDecodeError {}
