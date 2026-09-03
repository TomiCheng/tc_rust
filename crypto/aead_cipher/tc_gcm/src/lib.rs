//! Galois/Counter Mode (GCM) authenticated encryption.
//!
//! [`GcmBlockCipher`] is a streaming AEAD construction over a 16-byte block
//! cipher. AAD must be supplied before the first non-empty message input.
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_aes::AesEngine;
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_gcm::GcmBlockCipher;
//! use tc_params::AeadBlockParams;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 12];
//! let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
//! let mut encryptor = GcmBlockCipher::new(AesEngine::new());
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut ciphertext = [0_u8; 7 + 16];
//! let mut written = encryptor.process_bytes(b"message", &mut ciphertext)?;
//! written += encryptor.do_final(&mut ciphertext[written..])?;
//! assert_eq!(written, ciphertext.len());
//!
//! let mut decryptor = GcmBlockCipher::new(AesEngine::new());
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! let mut plaintext = [0_u8; 7];
//! let mut recovered = decryptor.process_bytes(&ciphertext, &mut plaintext)?;
//! recovered += decryptor.do_final(&mut plaintext[recovered..])?;
//! assert_eq!(recovered, plaintext.len());
//! assert_eq!(&plaintext, b"message");
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "alloc"))]
//! # fn main() {}
//! ```

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod engine;
#[cfg(feature = "alloc")]
mod ghash;

#[cfg(feature = "alloc")]
pub use engine::GcmBlockCipher;

/// Block size required by GCM in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Smallest supported authentication-tag size in bytes.
pub const MIN_MAC_BYTES: usize = 4;
/// Largest supported authentication-tag size in bytes.
pub const MAX_MAC_BYTES: usize = 16;
