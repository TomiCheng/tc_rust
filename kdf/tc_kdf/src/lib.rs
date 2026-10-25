//! Key derivation functions, after Bouncy Castle's `IDerivationFunction`:
//! a KDF turns a shared secret and optional context into as many key bytes
//! as the caller asks for.
//!
//! A shared secret from a key agreement, turned into an AES-128 key with KDF2
//! over SHA-256:
//!
//! ```
//! use tc_kdf::{Kdf, Kdf2, KdfInit, KdfParamsRef};
//! use tc_sha::Sha256Digest;
//!
//! // The shared secret, and the context the protocol specifies.
//! let shared_secret = [0x5a; 32];
//! let context = b"tc_kdf example";
//!
//! let mut kdf = Kdf2::new(Sha256Digest::new());
//! kdf.init(&KdfParamsRef::with_iv(&shared_secret, context))?;
//!
//! // The output length is the key length the cipher needs.
//! let mut key = [0u8; 16];
//! kdf.generate_bytes(&mut key)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

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
