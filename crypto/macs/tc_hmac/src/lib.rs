//! Hash-based message authentication code (HMAC).
//!
//! [`HMac`] accepts any infallible streaming [`Digest`](tc_digest::Digest)
//! and any key parameter implementing [`KeyParams`](tc_params::KeyParams).
//! Keys longer than the digest's internal block size are hashed first, as
//! specified by RFC 2104.
//!
//! ```
//! use tc_hmac::HMac;
//! use tc_macs::{Mac, MacInit};
//! use tc_params::KeyRef;
//! use tc_sha::Sha256Digest;
//!
//! let key = KeyRef::new(b"secret key");
//! let mut hmac = HMac::new(Sha256Digest::new());
//! hmac.init(&key).unwrap();
//! hmac.update(b"authenticated message").unwrap();
//!
//! let mut tag = [0_u8; 32];
//! assert_eq!(hmac.do_final(&mut tag), Ok(tag.len()));
//! ```

#![no_std]

extern crate alloc;

mod engine;

pub use engine::HMac;
