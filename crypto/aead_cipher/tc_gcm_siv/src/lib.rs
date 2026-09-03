//! AES-GCM-SIV authenticated encryption (RFC 8452).
//!
//! [`GcmSivBlockCipher`] is an allocation-backed packet mode: message input is
//! buffered by [`process_bytes`](tc_cipher::AeadCipher::process_bytes), and the
//! complete authenticated result is emitted by
//! [`do_final`](tc_cipher::AeadCipher::do_final). Decryption never releases
//! plaintext before its tag has been verified.
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_aes::AesEngine;
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_gcm_siv::GcmSivBlockCipher;
//! use tc_params::AeadBlockParams;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 12];
//! let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
//! let mut encryptor = GcmSivBlockCipher::new(AesEngine::new());
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//!
//! assert_eq!(encryptor.process_bytes(b"message", &mut [])?, 0);
//! let mut ciphertext = [0_u8; 7 + 16];
//! assert_eq!(encryptor.do_final(&mut ciphertext)?, ciphertext.len());
//!
//! let mut decryptor = GcmSivBlockCipher::new(AesEngine::new());
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! assert_eq!(decryptor.process_bytes(&ciphertext, &mut [])?, 0);
//! let mut plaintext = [0_u8; 7];
//! assert_eq!(decryptor.do_final(&mut plaintext)?, plaintext.len());
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
mod error;
#[cfg(feature = "alloc")]
mod polyval;

#[cfg(feature = "alloc")]
pub use engine::GcmSivBlockCipher;
#[cfg(feature = "alloc")]
pub use error::GcmSivInitError;

/// Block size required by GCM-SIV in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Nonce size required by GCM-SIV in bytes.
pub const NONCE_BYTES: usize = 12;
/// Authentication-tag size required by GCM-SIV in bytes.
pub const MAC_BYTES: usize = 16;
/// Maximum AAD or plaintext length allowed by RFC 8452.
pub const MAX_INPUT_BYTES: u64 = 1 << 36;
