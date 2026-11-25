//! The digest-based KDFs: KDF1 and KDF2 (ISO 18033-2, ANSI X9.63) and the
//! one-step concatenation KDF of SP 800-56C, over a shared secret and context.
//!
//! An ECDH shared secret turned into an AES-256 key with the X9.63 KDF, which
//! is KDF2, over SHA-256:
//!
//! ```
//! use tc_kdf::kdf::{Kdf2, KdfParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
//! use tc_sha::Sha256Digest;
//!
//! // Z from the agreement, and the SharedInfo both sides put after the counter.
//! let z = [0x5a; 32];
//! let shared_info = b"example protocol v1";
//!
//! let mut kdf = Kdf2::new(Sha256Digest::new());
//! kdf.init(&KdfParamsRef::with_iv(&z, shared_info))?;
//!
//! let mut key = [0u8; 32];
//! kdf.generate_bytes(&mut key)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

mod base_kdf;
mod concatenation_kdf;
mod params;
mod params_owned;
mod params_ref;

pub use base_kdf::{BaseKdf, Kdf1, Kdf2};
pub use concatenation_kdf::ConcatenationKdf;
pub use params::KdfParams;
pub use params_owned::KdfParamsOwned;
pub use params_ref::KdfParamsRef;
