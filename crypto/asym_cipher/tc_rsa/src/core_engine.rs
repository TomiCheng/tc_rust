//! The RSA operation without the CRT, as Bouncy Castle's `RsaCoreEngine`
//! runs it for a key that is not a CRT key: an engine for each kind of
//! integer, as for the CRT.

pub(crate) mod fixed;
#[cfg(feature = "alloc")]
mod padded;

pub use fixed::FixedRsaCoreEngine;
#[cfg(feature = "alloc")]
pub use padded::PaddedRsaCoreEngine;
