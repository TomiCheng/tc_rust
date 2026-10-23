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
#[cfg(feature = "sp800-108")]
mod sp800_108;
mod traits;

pub use base_kdf::{BaseKdf, Kdf1, Kdf2};
pub use concatenation_kdf::ConcatenationKdf;
pub use errors::KdfError;
#[cfg(feature = "sp800-108")]
pub use errors::KdfInitError;
#[cfg(feature = "hkdf")]
pub use hkdf::Hkdf;
#[cfg(feature = "hkdf")]
pub use params::HkdfParamsRef;
pub use params::KdfParamsRef;
#[cfg(feature = "sp800-108")]
pub use params::{KdfCounterParamsRef, KdfDoublePipelineParamsRef, KdfFeedbackParamsRef};
#[cfg(feature = "sp800-108")]
pub use sp800_108::{KdfCounter, KdfDoublePipeline, KdfFeedback};
#[cfg(feature = "hkdf")]
pub use traits::HkdfParams;
pub use traits::{Kdf, KdfInit, KdfParams};
#[cfg(feature = "sp800-108")]
pub use traits::{KdfCounterParams, KdfDoublePipelineParams, KdfFeedbackParams};
