//! HC family stream ciphers.

#![no_std]

pub mod hc128;
pub mod hc256;

pub use hc128::Hc128Engine;
pub use hc256::Hc256Engine;
