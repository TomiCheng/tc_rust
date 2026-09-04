//! Platform-sized integer words shared by the big-integer implementations.

#[cfg(target_pointer_width = "64")]
pub type Word = u64;
#[cfg(target_pointer_width = "64")]
pub type WideWord = u128;

#[cfg(not(target_pointer_width = "64"))]
pub type Word = u32;
#[cfg(not(target_pointer_width = "64"))]
pub type WideWord = u64;
