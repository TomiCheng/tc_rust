//! Offset Codebook (OCB3) authenticated encryption.
//!
//! OCB uses one block-cipher instance in the requested data direction and a
//! second instance in the encryption direction for hashing and offsets. Both
//! instances must be the same 16-byte block-cipher algorithm.
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_aes::AesEngine;
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_ocb::OcbBlockCipher;
//! use tc_params::AeadBlockParams;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 12];
//! let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
//! let mut encryptor = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//! encryptor.process_bytes(b"message", &mut [])?;
//! let mut ciphertext = [0_u8; 7 + 16];
//! encryptor.do_final(&mut ciphertext)?;
//!
//! let mut decryptor = OcbBlockCipher::new(AesEngine::new(), AesEngine::new());
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! decryptor.process_bytes(&ciphertext, &mut [])?;
//! let mut plaintext = [0_u8; 7];
//! decryptor.do_final(&mut plaintext)?;
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
pub use engine::OcbBlockCipher;

/// Block size required by OCB in bytes.
pub const BLOCK_BYTES: usize = 16;
/// Smallest supported authentication-tag size in bytes.
pub const MIN_MAC_BYTES: usize = 8;
/// Largest supported authentication-tag size in bytes.
pub const MAX_MAC_BYTES: usize = 16;
/// Largest supported nonce size in bytes.
pub const MAX_NONCE_BYTES: usize = 15;
