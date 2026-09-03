//! GMAC authentication over GCM.
//!
//! [`GMac`] is the authentication-only specialization of GCM: every byte
//! passed to [`Mac::update`](tc_macs::Mac::update) is processed as associated
//! data, and no plaintext is encrypted.
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_aes::AesEngine;
//! use tc_gmac::GMac;
//! use tc_macs::{Mac, MacInit};
//! use tc_params::KeyWithIvRef;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 12];
//! let params = KeyWithIvRef::new(&key, &nonce);
//! let mut mac = GMac::new(AesEngine::new())?;
//! mac.init(&params)?;
//! mac.update(b"authenticated but not encrypted")?;
//!
//! let mut tag = [0_u8; 16];
//! assert_eq!(mac.do_final(&mut tag)?, tag.len());
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "alloc"))]
//! # fn main() {}
//! ```
//!
//! A completed GMAC remains finalized. Initialize it again with a fresh nonce
//! before authenticating another message under the same key.

#![no_std]

#[cfg(feature = "alloc")]
mod engine;
mod error;

#[cfg(feature = "alloc")]
pub use engine::GMac;
pub use error::CreateError;

/// Default and largest GMAC tag size in bytes.
pub const MAX_MAC_BYTES: usize = 16;
/// Smallest supported GMAC tag size in bytes.
pub const MIN_MAC_BYTES: usize = 4;
