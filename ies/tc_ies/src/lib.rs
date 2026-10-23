//! The Integrated Encryption Scheme, after Bouncy Castle's `IesEngine`: a key agreement gives
//! a shared secret, a KDF turns it into an encryption key and a MAC key, and the message is
//! encrypted and tagged with them.

#![no_std]

mod params;
mod traits;

#[cfg(feature = "cipher")]
pub use params::IesCipherParamsRef;
pub use params::IesParamsRef;
#[cfg(feature = "cipher")]
pub use traits::IesCipherParams;
pub use traits::IesParams;
