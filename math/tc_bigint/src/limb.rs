//! Platform-sized integer words shared by the big-integer implementations.

#[cfg(target_pointer_width = "64")]
pub(crate) type Limb = u64;
#[cfg(target_pointer_width = "64")]
pub(crate) type DoubleLimb = u128;

#[cfg(not(target_pointer_width = "64"))]
pub(crate) type Limb = u32;
#[cfg(not(target_pointer_width = "64"))]
pub(crate) type DoubleLimb = u64;
