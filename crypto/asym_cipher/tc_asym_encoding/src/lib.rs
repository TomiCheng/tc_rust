//! Encodings over asymmetric block ciphers, after Bouncy Castle's
//! `crypto/encodings`: PKCS#1 v1.5, OAEP and ISO 9796-1, each wrapping an
//! engine as an asymmetric block cipher of its own.

#![no_std]

extern crate alloc;

mod error;
mod pkcs1_encoding;

pub use error::EncodingError;
pub use pkcs1_encoding::Pkcs1Encoding;
