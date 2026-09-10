//! Explicit erasure of heap-backed containers.

use crate::Zeroize;
use alloc::{boxed::Box, vec::Vec};

impl<T: Zeroize> Zeroize for Vec<T> {
    fn zeroize(&mut self) {
        // Wipe the live elements first, so a destructor that reads its own
        // value observes the cleared one, matching `Option<T>`.
        self.as_mut_slice().zeroize();
        // Dropping the elements frees the length without releasing the buffer.
        self.clear();
        // The spare slice now spans the whole allocation.
        self.spare_capacity_mut().zeroize();
    }
}

impl<T: Zeroize + ?Sized> Zeroize for Box<T> {
    fn zeroize(&mut self) {
        (**self).zeroize();
    }
}
