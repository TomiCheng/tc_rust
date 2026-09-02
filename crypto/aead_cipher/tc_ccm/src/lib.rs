//! Counter with CBC-MAC (CCM) authenticated encryption.
//!
//! CCM is a packet mode and therefore buffers all AAD and message data until
//! finalization. [`CcmBlockCipher`] is available with the default `alloc`
//! feature and does not require `std`.
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_aes::AesEngine;
//! use tc_ccm::CcmBlockCipher;
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_params::AeadBlockParams;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 12];
//! let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
//! let mut encryptor = CcmBlockCipher::new(AesEngine::new());
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//!
//! // Packet mode buffers this call and emits everything at finalization.
//! assert_eq!(encryptor.process_bytes(b"message", &mut [])?, 0);
//! let mut ciphertext = [0_u8; 7 + 16];
//! let written = encryptor.do_final(&mut ciphertext)?;
//! assert_eq!(written, ciphertext.len());
//!
//! let mut decryptor = CcmBlockCipher::new(AesEngine::new());
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! assert_eq!(decryptor.process_bytes(&ciphertext, &mut [])?, 0);
//! let mut recovered = [0_u8; 7];
//! let recovered_len = decryptor.do_final(&mut recovered)?;
//! assert_eq!(recovered_len, recovered.len());
//! assert_eq!(&recovered, b"message");
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
pub use engine::CcmBlockCipher;

/// Block size required by CCM in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Smallest CCM nonce size in bytes.
pub const MIN_NONCE_BYTES: usize = 7;
/// Largest CCM nonce size in bytes.
pub const MAX_NONCE_BYTES: usize = 13;
/// Smallest CCM authentication-tag size in bytes.
pub const MIN_MAC_BYTES: usize = 4;
/// Largest CCM authentication-tag size in bytes.
pub const MAX_MAC_BYTES: usize = 16;
