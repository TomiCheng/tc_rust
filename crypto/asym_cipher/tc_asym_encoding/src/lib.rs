//! Encodings over asymmetric block ciphers, after Bouncy Castle's
//! `crypto/encodings`: PKCS#1 v1.5, OAEP and ISO 9796-1, each wrapping an
//! engine as an asymmetric block cipher of its own. ISO 9796-1 reads the
//! modulus of an RSA key, and so comes with the `iso9796` feature, which
//! takes in the RSA crate.

#![no_std]

extern crate alloc;

mod error;
#[cfg(feature = "iso9796")]
mod iso9796d1_encoding;
mod oaep_encoding;
mod pkcs1_encoding;

pub use error::EncodingError;
#[cfg(feature = "iso9796")]
pub use iso9796d1_encoding::Iso9796d1Encoding;
pub use oaep_encoding::OaepEncoding;
pub use pkcs1_encoding::Pkcs1Encoding;
