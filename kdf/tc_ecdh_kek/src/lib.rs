//! The RFC 5753 ECDH KEK derivation for CMS, after Bouncy Castle's
//! `ECDHKekGenerator`: the X9.63 KDF (KDF2) over the shared secret Z, with the
//! DER `ECC-CMS-SharedInfo` that names the wrap algorithm, the sender's user
//! keying material and the KEK length as its shared info.
//!
//! A CMS recipient's AES-256 key-wrap key from an ephemeral-static ECDH shared
//! secret, under `dhSinglePass-stdDH-sha256kdf-scheme`:
//!
//! ```
//! use tc_ecdh_kek::{EcdhKek, EcdhKekParamsRef};
//! use tc_kdf::{Kdf, KdfInit};
//! use tc_sha::Sha256Digest;
//! use tc_asn1_x509::alg::AlgorithmIdentifier;
//!
//! // Z from ECDH, the wrap algorithm as the sender wrote it, and the sender's UKM.
//! let z = [0x5a; 32];
//! let aes256_wrap = AlgorithmIdentifier::new("2.16.840.1.101.3.4.1.45".parse()?);
//! let ukm = [0x42; 64];
//!
//! let mut kek = EcdhKek::new(Sha256Digest::new());
//! kek.init(&EcdhKekParamsRef::with_extra_info(&aes256_wrap, 256, &z, &ukm))?;
//!
//! // The KEK is as long as the wrap algorithm's key: 256 bits.
//! let mut key = [0u8; 32];
//! kek.generate_bytes(&mut key)?;
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [`RawUkmKek`] is the non-conformant variant some senders used, for reading
//! their messages only.

#![no_std]

extern crate alloc;

mod ecdh_kek;
mod params;
mod raw_ukm_kek;

pub use ecdh_kek::EcdhKek;
pub use params::{EcdhKekParams, EcdhKekParamsRef};
pub use raw_ukm_kek::RawUkmKek;
