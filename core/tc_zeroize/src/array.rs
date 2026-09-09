//! Element-wise erasure of fixed-size arrays.

use crate::Zeroize;

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}
