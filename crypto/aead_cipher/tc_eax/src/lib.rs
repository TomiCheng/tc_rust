//! EAX authenticated encryption over a 64- or 128-bit block cipher.
//!
//! EAX combines CTR encryption with three domain-separated CMAC calculations.
//! [`EaxBlockCipher`] produces full blocks during
//! [`process_bytes`](tc_cipher::AeadCipher::process_bytes) and emits the final
//! partial block and tag during [`do_final`](tc_cipher::AeadCipher::do_final).
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_aes::AesEngine;
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_eax::EaxBlockCipher;
//! use tc_params::AeadBlockParams;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 16];
//! let params = AeadBlockParams::new(&key, &nonce, 16, b"header");
//! let mut encryptor = EaxBlockCipher::new(AesEngine::new());
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//! let mut ciphertext = [0_u8; 7 + 16];
//! let mut written = encryptor.process_bytes(b"message", &mut ciphertext)?;
//! written += encryptor.do_final(&mut ciphertext[written..])?;
//! assert_eq!(written, ciphertext.len());
//!
//! let mut decryptor = EaxBlockCipher::new(AesEngine::new());
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! let mut plaintext = [0_u8; 7];
//! let mut recovered = decryptor.process_bytes(&ciphertext, &mut plaintext)?;
//! recovered += decryptor.do_final(&mut plaintext[recovered..])?;
//! assert_eq!(&plaintext[..recovered], b"message");
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
pub use engine::EaxBlockCipher;
#[cfg(feature = "alloc")]
pub use error::EaxInitError;

/// Smallest supported authentication-tag size in bytes.
pub const MIN_MAC_BYTES: usize = 4;
/// Largest supported block and authentication-tag size in bytes.
pub const MAX_BLOCK_BYTES: usize = 16;
