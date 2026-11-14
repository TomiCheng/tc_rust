//! Digests, which hash a message of any length to a fixed size.
//!
//! An [`Algo`](crate::Algo) finds them by name or OID:
//!
//! ```
//! # #[cfg(feature = "sha256")] {
//! use tc_algo::{AlgoBuilder, DefaultAlgoBuilder};
//!
//! let algo = DefaultAlgoBuilder::default().build();
//!
//! let mut digest = algo.digest().get_by_name("SHA-256").unwrap();
//! digest.try_update(b"abc").unwrap();
//! let hash = digest.finalize().unwrap();
//! assert_eq!(hash.len(), 32);
//! # }
//! ```

mod algo;
mod default_digest_provider;
mod digest_entry;
mod digest_provider;
mod digest_trait;
mod empty_digest_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use digest_entry::DigestEntry;
pub use digest_provider::DigestProvider;
pub use digest_trait::Digest;
pub use tc_digest::TryDigest;
pub(crate) use empty_digest_provider::EmptyDigestProvider;
