//! ISO/IEC 9796 digital signatures with message recovery, after Bouncy
//! Castle: part 1, its `ISO9796d1Encoding`, and part 2, its
//! `Iso9796d2Signer`. Both read the modulus of an RSA key, and so take RSA
//! in, unlike the encodings that wrap any asymmetric engine.

#![no_std]

extern crate alloc;

mod error;
mod iso9796d1_encoding;

pub use error::Iso9796Error;
pub use iso9796d1_encoding::Iso9796d1Encoding;
