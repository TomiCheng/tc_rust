//! Digests by name or OID, after Bouncy Castle's `DigestUtilities`.
//!
//! ```
//! # #[cfg(feature = "sha256")] {
//! use tc_algo::digest::{self, Algorithm};
//!
//! // In pieces: get a digest, feed it, then finish
//! let mut sha256 = digest::get(Algorithm::Sha256);
//! sha256.update(b"hello, ");
//! sha256.update(b"world");
//! let hash = sha256.finalize();
//!
//! // All at once
//! assert_eq!(digest::calculate(Algorithm::Sha256, b"hello, world"), hash);
//!
//! // When the algorithm comes from configuration or ASN.1, name it or give its OID
//! let by_name = digest::calculate_by_name("SHA-256", b"hello, world")?;
//! # assert_eq!(by_name, hash);
//! # }
//! # Ok::<(), tc_algo::AlgoError>(())
//! ```

mod algorithm;
mod any_digest;
mod dyn_digest;
mod entry;
mod functions;
mod helper;
mod table;

pub use algorithm::Algorithm;
pub use any_digest::AnyDigest;
pub use entry::DigestEntry;
pub use functions::{algorithms, get, get_by_name, get_by_oid};
pub use helper::{
    calculate, calculate_by_name, calculate_by_name_into, calculate_by_oid, calculate_by_oid_into,
    calculate_into,
};
pub use tc_digest::{Digest, TryDigest};
