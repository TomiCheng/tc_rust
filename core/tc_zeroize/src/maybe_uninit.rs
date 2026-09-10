//! Volatile erasure of possibly uninitialized storage.

use crate::Zeroize;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

impl<T> Zeroize for MaybeUninit<T> {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, uniquely borrowed place. `MaybeUninit<T>`
        // has no validity invariant, so an all-zero pattern is always legal for
        // it, and no destructor is skipped because the slot is never treated as
        // initialized. Volatility changes optimization semantics, not validity.
        unsafe { ptr::write_volatile(self, MaybeUninit::zeroed()) };
        compiler_fence(Ordering::SeqCst);
    }
}
