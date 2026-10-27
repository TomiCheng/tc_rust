//! scrypt of RFC 7914, by Colin Percival: [`Scrypt`] is BC's `SCrypt`, a password-based key
//! derivation that needs `128 * r * N` bytes of memory as well as time, so that custom hardware
//! gains little over a computer.
//!
//! An AES-256 key from a passphrase, for encrypting a file:
//!
//! ```
//! use tc_pwhash::scrypt::Scrypt;
//!
//! // A fresh random salt, stored beside the ciphertext.
//! let salt = [0x5c; 16];
//!
//! // N = 2^14, r = 8, p = 1: 16 MiB, Percival's figures for interactive use; a file can
//! // afford more.
//! let mut key = [0u8; 32];
//! Scrypt::generate(b"correct horse", &salt, 1 << 14, 8, 1, &mut key)?;
//! # Ok::<(), tc_pwhash::scrypt::ScryptError>(())
//! ```

mod generator;
mod ro_mix;
mod salsa;
mod scrypt_error;

pub use generator::Scrypt;
pub use scrypt_error::ScryptError;
