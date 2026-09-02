//! Data Encryption Standard (DES) and Triple DES implementations.
//!
//! These algorithms are retained for compatibility with legacy protocols and
//! are not suitable for new designs.

#![no_std]

mod cipher;
mod des;
mod des_ede;

pub use des::DesEngine;
pub use des_ede::DesEdeEngine;

/// DES key length in bytes (64 encoded bits, 56 effective bits).
pub const KEY_BYTES: usize = 8;
/// DES and Triple DES block length in bytes.
pub const BLOCK_BYTES: usize = 8;
/// Encoded key length for two-key Triple DES (`K1, K2, K1`).
pub const EDE2_KEY_BYTES: usize = 16;
/// Encoded key length for three-key Triple DES (`K1, K2, K3`).
pub const EDE3_KEY_BYTES: usize = 24;
