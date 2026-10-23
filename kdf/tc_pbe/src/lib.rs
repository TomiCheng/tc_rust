//! Password-based key derivation for PBE, after Bouncy Castle's `PbeParametersGenerator`:
//! a password, a salt and an iteration count give a cipher key, optionally with an IV, or a
//! MAC key.

#![no_std]

extern crate alloc;

mod params;
mod password;
mod traits;

pub use params::PbeParamsRef;
pub use password::{
    pkcs5_password_to_bytes, pkcs5_password_to_utf8_bytes, pkcs12_password_to_bytes,
};
pub use traits::{PbeGenerator, PbeGeneratorInit, PbeParams};
