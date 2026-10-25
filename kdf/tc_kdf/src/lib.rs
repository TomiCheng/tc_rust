//! Key derivation functions, after Bouncy Castle's `IDerivationFunction`:
//! a KDF turns a shared secret and optional context into as many key bytes
//! as the caller asks for.
//!
//! - [`kdf`]: KDF1, KDF2 and the concatenation KDF, over a digest.
//! - [`hkdf`]: HKDF, over HMAC.
//! - [`sp800_108`]: the SP 800-108 counter, feedback and double-pipeline
//!   KDFs, over any MAC.
//!
//! [`Kdf`] and [`KdfInit`] are what every function implements, and
//! [`KdfError`] what they all report.
//!
//! A shared secret from a key agreement, turned into an AES-128 key with KDF2
//! over SHA-256:
//!
//! ```
//! use tc_kdf::kdf::{Kdf2, KdfParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
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

mod errors;
pub mod hkdf;
pub mod kdf;
pub mod sp800_108;
mod traits;

pub use errors::KdfError;
pub use traits::{Kdf, KdfInit};
