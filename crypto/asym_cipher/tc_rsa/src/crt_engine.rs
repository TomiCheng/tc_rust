//! The RSA operation with the CRT, as Bouncy Castle's `RsaCoreEngine` runs
//! it for a CRT key: an engine for each kind of integer, as the widths of
//! the modulus and of the primes cross differently in each.

mod fixed;
#[cfg(feature = "alloc")]
mod padded;

pub use fixed::FixedRsaCrtCoreEngine;
#[cfg(feature = "alloc")]
pub use padded::PaddedRsaCrtCoreEngine;
