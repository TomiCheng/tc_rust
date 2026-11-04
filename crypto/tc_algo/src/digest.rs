//! Digests by name or OID, after Bouncy Castle's `DigestUtilities`.
//!
//! ```
//! # #[cfg(feature = "sha256")] {
//! use tc_algo::digest;
//!
//! // In pieces: get a digest by its name, or by its OID, feed it, then finish
//! let mut sha256 = digest::get_by_name("SHA-256")?;
//! sha256.update(b"hello, ");
//! sha256.update(b"world");
//! let hash = sha256.finalize();
//!
//! // All at once
//! assert_eq!(digest::calculate_by_name("SHA-256", b"hello, world")?, hash);
//! # }
//! # Ok::<(), tc_algo::AlgoError>(())
//! ```

mod any_digest;
mod dyn_digest;
mod entry;
#[cfg(feature = "haraka")]
mod fixed_input;
mod functions;
mod helper;
mod table;

pub use any_digest::AnyDigest;
pub use entry::DigestEntry;
pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::{
    calculate_by_name, calculate_by_name_into, calculate_by_oid, calculate_by_oid_into,
};
pub use tc_digest::{Digest, TryDigest};
