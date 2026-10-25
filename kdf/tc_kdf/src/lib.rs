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
//! The common case: an ECDH shared secret turned into an AES-256-GCM key with
//! HKDF-SHA256.
//!
//! ```
//! use tc_kdf::hkdf::{Hkdf, HkdfParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
//! use tc_sha::Sha256Digest;
//!
//! // The shared secret, a salt both sides know, and the label the protocol
//! // gives this key.
//! let shared_secret = [0x5a; 32];
//! let salt = [0xa5; 32];
//! let info = b"example protocol v1: encryption key";
//!
//! let mut hkdf = Hkdf::new(Sha256Digest::new());
//! hkdf.init(&HkdfParamsRef::new(&shared_secret, &salt, info))?;
//!
//! // The output length is the key length the cipher needs.
//! let mut key = [0u8; 32];
//! hkdf.generate_bytes(&mut key)?;
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
