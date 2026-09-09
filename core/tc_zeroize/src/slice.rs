//! Element-wise erasure of slices with public lengths.

use crate::Zeroize;
use core::sync::atomic::{Ordering, compiler_fence};

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        for value in self {
            value.zeroize();
        }
        compiler_fence(Ordering::SeqCst);
    }
}
