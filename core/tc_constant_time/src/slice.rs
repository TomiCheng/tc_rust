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
