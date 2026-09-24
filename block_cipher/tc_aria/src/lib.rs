//! ARIA-128, ARIA-192, and ARIA-256 block cipher as specified by RFC 5794.
//!
//! [`AriaEngine`] accepts 16-, 24- or 32-byte keys and processes 16-byte blocks.
//! Import [`BlockCipherInit`](tc_block_cipher::BlockCipherInit) and
//! [`BlockCipher`](tc_block_cipher::BlockCipher) to initialize and use it.
//! See the engine's example for encryption and decryption.
//!
//! # Backend selection
//!
//! With the `rustcrypto` feature, `AriaEngine` delegates to
//! `AriaRustCryptoEngine`, backed by the RustCrypto `aria` crate.
//! Without it, the engine delegates to [`AriaTableEngine`].
//! Both implementations are also available for direct use when enabled.
//!
//! # Security
//!
//! Neither backend is **constant time**: both key setup and
//! block processing use secret-dependent table lookups. It is unsuitable where
//! cache-timing attacks are in scope. Stored schedules are wiped on drop, but
//! callers remain responsible for their input keys and other copies.
//!
//! This is a block-cipher primitive, not message encryption. It provides no
//! padding, nonce handling, mode or authentication. Use an appropriate
//! authenticated-encryption construction for messages.
//!
//! The crate is `no_std` and requires no allocator.

#![no_std]

mod cipher;
mod engine;
#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod table_engine;

pub use engine::AriaEngine;
#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::AriaRustCryptoEngine;
pub use table_engine::AriaTableEngine;

/// Algorithm name returned by the engine's `Display` implementation.
pub const ALGO_NAME: &str = "ARIA";
/// ARIA block length in bytes (128 bits), independent of key size.
pub const BLOCK_BYTES: usize = 16;
/// Accepted key lengths in bytes (128, 192 and 256 bits).
pub const KEY_BYTES: [usize; 3] = [16, 24, 32];
