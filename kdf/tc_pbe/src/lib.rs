//! Password-based key derivation for PBE, after Bouncy Castle's `PbeParametersGenerator`:
//! a password, a salt and an iteration count give a cipher key, optionally with an IV, or a
//! MAC key.

#![no_std]

extern crate alloc;

mod errors;
mod openssl_pbe;
mod params;
mod password;
mod pkcs12;
mod pkcs5_s1;
#[cfg(feature = "pbkdf2")]
mod pkcs5_s2;
mod state;
mod traits;

pub use errors::PbeError;
pub use openssl_pbe::OpenSslPbe;
pub use params::PbeParamsRef;
pub use password::{
    pkcs5_password_to_bytes, pkcs5_password_to_utf8_bytes, pkcs12_password_to_bytes,
};
pub use pkcs5_s1::Pkcs5S1;
#[cfg(feature = "pbkdf2")]
pub use pkcs5_s2::Pkcs5S2;
pub use pkcs12::Pkcs12;
pub use traits::{PbeGenerator, PbeGeneratorInit, PbeParams};
