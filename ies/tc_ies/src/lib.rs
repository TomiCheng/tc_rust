//! The Integrated Encryption Scheme, after Bouncy Castle's `IesEngine`: a key agreement gives
//! a shared secret, a KDF turns it into an encryption key and a MAC key, and the message is
//! encrypted and tagged with them.

#![no_std]

extern crate alloc;

mod errors;
#[cfg(feature = "cipher")]
mod ies_cipher_engine;
mod ies_engine;
mod params;
mod steps;
mod traits;

pub use errors::{IesError, PrimitiveError};
#[cfg(feature = "cipher")]
pub use ies_cipher_engine::IesCipherEngine;
pub use ies_engine::IesEngine;
#[cfg(feature = "cipher")]
pub use params::IesCipherParamsRef;
pub use params::IesParamsRef;
#[cfg(feature = "cipher")]
pub use traits::IesCipherParams;
pub use traits::IesParams;
