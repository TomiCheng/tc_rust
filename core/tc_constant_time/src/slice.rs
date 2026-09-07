//! Constant-time equality for slices with public lengths.

use crate::{Choice, ConstantTimeEq};

/// Slice lengths are public and may cause an early return when they differ.
/// Equal-length slices compare all elements; empty slices compare equal.
///
/// ```
/// use tc_constant_time::ConstantTimeEq;
/// let a: &[u16] = &[1, 2];
/// let b: &[u16] = &[1, 3];
/// assert_eq!(a.ct_eq(b).unwrap_u8(), 0);
/// assert_eq!(a.ct_eq(&a[..1]).unwrap_u8(), 0);
/// assert_eq!(a.ct_eq(a).unwrap_u8(), 1);
/// ```
impl<T: ConstantTimeEq> ConstantTimeEq for [T] {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        if self.len() != rhs.len() {
            return Choice::from_lsb(0);
        }
        let mut equal = Choice(1);
        for (left, right) in self.iter().zip(rhs) {
            equal = equal & left.ct_eq(right);
        }
        equal
    }
}

/// Compares byte slices and deliberately reveals the equality result.
///
/// Use this convenience function only when the verification result is intended
/// to be public, such as authentication-tag verification. For intermediate
/// secret predicates, use [`ConstantTimeEq::ct_eq`] and retain the [`Choice`].
///
/// Lengths are public: different lengths return `false` immediately. Equal
/// lengths scan every byte, without an early exit on a mismatch. Empty slices
/// compare equal. This contract does not hide slice lengths.
///
/// ```
/// use tc_constant_time::fixed_time_eq;
/// assert!(fixed_time_eq(b"tag", b"tag"));
/// assert!(!fixed_time_eq(b"tag", b"tam"));
/// assert!(!fixed_time_eq(b"tag", b"tag\0"));
/// assert!(fixed_time_eq(b"", b""));
/// ```
pub fn fixed_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}
