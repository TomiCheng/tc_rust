//! Password-based key derivation for PBE, after Bouncy Castle's `PbeParametersGenerator`:
//! a password, a salt and an iteration count give a cipher key, optionally with an IV, or a
//! MAC key.

#![no_std]

mod params;
mod traits;

pub use params::PbeParamsRef;
pub use traits::{PbeGenerator, PbeGeneratorInit, PbeParams};
