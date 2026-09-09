//! Volatile erasure of primitive values.

use crate::Zeroize;
use core::ptr;
use core::sync::atomic::{Ordering, compiler_fence};

macro_rules! impl_zeroize {
    ($($ty:ty => $zero:expr),+ $(,)?) => {
        $(
            impl Zeroize for $ty {
                fn zeroize(&mut self) {
                    // SAFETY: `self` is a valid, uniquely borrowed value, and
                    // the replacement is valid for this primitive type.
                    // Volatility changes optimization semantics, not validity.
                    unsafe { ptr::write_volatile(self, $zero) };
                    compiler_fence(Ordering::SeqCst);
                }
            }
        )+
    };
}

impl_zeroize! {
    u8 => 0, u16 => 0, u32 => 0, u64 => 0, u128 => 0, usize => 0,
    i8 => 0, i16 => 0, i32 => 0, i64 => 0, i128 => 0, isize => 0,
    bool => false, char => '\0',
}
