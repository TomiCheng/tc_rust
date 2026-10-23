//! Key derivation functions, after Bouncy Castle's `IDerivationFunction`:
//! a KDF turns a shared secret and optional context into as many key bytes
//! as the caller asks for.

#![no_std]

mod errors;
mod params;
mod traits;

pub use errors::KdfError;
pub use params::KdfParamsRef;
pub use traits::{Kdf, KdfInit, KdfParams};
