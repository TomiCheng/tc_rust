//! Key derivation functions, after Bouncy Castle's `IDerivationFunction`:
//! a KDF turns a shared secret and optional context into as many key bytes
//! as the caller asks for.

#![no_std]

extern crate alloc;

mod base_kdf;
mod concatenation_kdf;
mod errors;
#[cfg(feature = "hkdf")]
mod hkdf;
mod params;
mod traits;

pub use base_kdf::{BaseKdf, Kdf1, Kdf2};
pub use concatenation_kdf::ConcatenationKdf;
pub use errors::KdfError;
#[cfg(feature = "hkdf")]
pub use hkdf::Hkdf;
#[cfg(feature = "hkdf")]
pub use params::HkdfParamsRef;
pub use params::KdfParamsRef;
#[cfg(feature = "hkdf")]
pub use traits::HkdfParams;
pub use traits::{Kdf, KdfInit, KdfParams};
