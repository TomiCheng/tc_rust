//! MACs by name or OID, after Bouncy Castle's `MacUtilities`. A MAC is found by name, initialized
//! with an [`AnyMacParams`] that holds the key and, for the MACs that take one, an IV, then fed the
//! message for its tag.
//!
//! ```
//! # #[cfg(all(feature = "hmac", feature = "sha256"))] {
//! use tc_algo::mac::{self, AnyMacParams};
//! use tc_algo::params::SecretKey;
//!
//! let params = AnyMacParams::new(SecretKey::new(b"a secret key".to_vec()));
//!
//! // In pieces: find a MAC, initialize it, feed it, then finish
//! let mut hmac = mac::get_by_name("HMAC-SHA256")?;
//! hmac.init(&params)?;
//! hmac.update(b"hello, ")?;
//! hmac.update(b"world")?;
//! let tag = hmac.finalize()?;
//!
//! // All at once
//! assert_eq!(mac::calculate("HMAC-SHA256", &params, b"hello, world")?, tag);
//!
//! // Checking a tag you received, in constant time
//! hmac.update(b"hello, world")?;
//! assert!(hmac.verify(&tag)?);
//! # }
//! # Ok::<(), tc_algo::AlgoError>(())
//! ```

mod any_mac;
mod any_mac_params;
#[cfg(feature = "hmac")]
mod classify;
mod dyn_mac;
mod entry;
mod functions;
mod helper;
mod table;

pub use any_mac::AnyMac;
pub use any_mac_params::AnyMacParams;
pub use entry::MacEntry;
pub use functions::{algorithms, get_by_name, get_by_oid};
pub use helper::calculate;
pub use tc_macs::{Mac, MacInit};
