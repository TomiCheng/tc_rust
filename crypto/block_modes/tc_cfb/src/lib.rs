//! Cipher Feedback (CFB) modes.
//!
//! Standard CFB processes configurable-size segments and feeds ciphertext back
//! into a block-sized register. OpenPGP CFB uses full blocks and performs the
//! protocol's two-byte resynchronization after the first block.
//!
//! [`FixedCfbBlockCipher`] and [`FixedOpenPgpCfbBlockCipher`] keep all state in
//! fixed-size arrays and require no allocation. The default `alloc` feature
//! additionally provides the runtime-sized `CfbBlockCipher` and
//! `OpenPgpCfbBlockCipher` types.

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod fixed_cfb;
mod fixed_openpgp;

#[cfg(feature = "alloc")]
mod cfb;
#[cfg(feature = "alloc")]
mod openpgp;

#[cfg(feature = "alloc")]
pub use cfb::CfbBlockCipher;
pub use fixed_cfb::FixedCfbBlockCipher;
pub use fixed_openpgp::FixedOpenPgpCfbBlockCipher;
#[cfg(feature = "alloc")]
pub use openpgp::OpenPgpCfbBlockCipher;
