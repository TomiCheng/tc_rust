//! A scope guard for opt-in erasure.

use crate::{Zeroize, ZeroizeOnDrop};
use core::ops::{Deref, DerefMut};

/// Owns a value and calls [`Zeroize::zeroize`] before dropping it.
///
/// The guard implements neither `Clone` nor `Copy`. Borrowing its contents is
/// supported, but copying or cloning the inner value produces a separate value
/// outside this guard's protection. Moving into the guard may also leave bytes
/// in the old location. Cleanup requires the guard's destructor to run.
///
/// ```
/// use tc_zeroize::Zeroizing;
/// let mut secret = Zeroizing::new([9_u8; 4]);
/// secret[0] = 3;
/// assert_eq!(&*secret, &[3, 9, 9, 9]);
/// ```
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Takes ownership of a value to erase when this guard is dropped.
    pub fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> Deref for Zeroizing<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Zeroize> DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Zeroizing<T> {}
