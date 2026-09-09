//! Erasure of an optional value before it is removed.

use crate::Zeroize;
use core::sync::atomic::{Ordering, compiler_fence};

impl<T: Zeroize> Zeroize for Option<T> {
    fn zeroize(&mut self) {
        if let Some(value) = self.as_mut() {
            value.zeroize();
        }
        // Assignment drops the cleared payload; a volatile replacement would
        // skip its destructor. Only the payload's erasure needs volatile stores.
        *self = None;
        compiler_fence(Ordering::SeqCst);
    }
}
