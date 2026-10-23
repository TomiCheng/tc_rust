//! Password-based key derivation for PBE, after Bouncy Castle's `PbeParametersGenerator`:
//! a password, a salt and an iteration count give a cipher key, optionally with an IV, or a
//! MAC key.

#![no_std]

extern crate alloc;

mod errors;
mod params;
mod password;
mod pkcs5_s1;
mod traits;

pub use errors::PbeError;
pub use params::PbeParamsRef;
pub use password::{
    pkcs5_password_to_bytes, pkcs5_password_to_utf8_bytes, pkcs12_password_to_bytes,
};
pub use pkcs5_s1::Pkcs5S1;
pub use traits::{PbeGenerator, PbeGeneratorInit, PbeParams};
