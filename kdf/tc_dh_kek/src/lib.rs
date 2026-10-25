//! The RFC 2631 (X9.42) Diffie-Hellman KEK derivation, after Bouncy Castle's
//! `DHKekGenerator`: each block hashes the shared secret ZZ followed by the DER
//! `OtherInfo` that names the wrap algorithm, the block counter and the KEK length.
//!
//! A CMS recipient's AES-256 key-wrap key from a Diffie-Hellman shared secret:
//!
//! ```
//! use tc_asn1::Asn1Oid;
//! use tc_dh_kek::{DhKek, DhKekParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
//! use tc_sha::Sha256Digest;
//!
//! // The shared secret ZZ, and the wrap algorithm the KEK is for.
//! let zz = [0x5a; 256];
//! let aes256_wrap: Asn1Oid = "2.16.840.1.101.3.4.1.45".parse()?;
//!
//! let mut kek = DhKek::new(Sha256Digest::new());
//! kek.init(&DhKekParamsRef::new(&aes256_wrap, 256, &zz))?;
//!
//! // The KEK is as long as the wrap algorithm's key: 256 bits.
//! let mut key = [0u8; 32];
//! kek.generate_bytes(&mut key)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

mod dh_kek;
mod params;

pub use dh_kek::DhKek;
pub use params::{DhKekParams, DhKekParamsRef};
