#![no_std]

//! ANSI X9 structures without group or curve arithmetic, by group:
//!
//! - [`ec`]: X9.62 and SEC 1 elliptic-curve parameters, private keys and
//!   ECDSA signatures.
//! - [`dh`]: X9.42 Diffie-Hellman domain parameters and public keys.
//! - [`kdf`]: the X9.42 KEK derivation context.
//!
//! [`X9Algorithm`] holds the algorithm and scheme identifiers the groups share.

extern crate alloc;

pub mod dh;
pub mod ec;
pub mod kdf;
mod x9_algorithm;

pub use x9_algorithm::X9Algorithm;
