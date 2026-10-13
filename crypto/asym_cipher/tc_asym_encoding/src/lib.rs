//! Encodings over asymmetric block ciphers, after Bouncy Castle's
//! `crypto/encodings`: PKCS#1 v1.5 and OAEP, each wrapping an engine as an
//! asymmetric block cipher of its own. Bouncy Castle's ISO 9796-1, which
//! reads the modulus of an RSA key, is left to a crate of its own.

#![no_std]

extern crate alloc;

mod error;
mod oaep_encoding;
mod pkcs1_encoding;

pub use error::EncodingError;
pub use oaep_encoding::OaepEncoding;
pub use pkcs1_encoding::Pkcs1Encoding;
