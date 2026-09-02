//! ChaCha authenticated-encryption algorithms.
//!
//! This crate implements RFC 8439 ChaCha20-Poly1305 and XChaCha20-Poly1305.
//!
//! # Example
//!
//! ```
//! use tc_chacha_aead::{ChaCha20Poly1305, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = [0x11_u8; KEY_BYTES];
//! let nonce = [0x22_u8; NONCE_BYTES];
//! let params = Params::new(&key, &nonce, b"header");
//! let plaintext = b"message";
//! let mut ciphertext = [0_u8; 7 + TAG_BYTES];
//!
//! let mut encryptor = ChaCha20Poly1305::new();
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//! let mut written = encryptor.process_bytes(plaintext, &mut ciphertext)?;
//! written += encryptor.do_final(&mut ciphertext[written..])?;
//! assert_eq!(written, ciphertext.len());
//!
//! let mut decryptor = ChaCha20Poly1305::new();
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! let mut recovered = [0_u8; 7];
//! let mut recovered_len = decryptor.process_bytes(&ciphertext, &mut recovered)?;
//! recovered_len += decryptor.do_final(&mut recovered[recovered_len..])?;
//! assert_eq!(&recovered[..recovered_len], plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! XChaCha20-Poly1305 uses the same API with a 24-byte nonce:
//!
//! ```
//! use tc_chacha_aead::{Params, XChaCha20Poly1305, XNONCE_BYTES};
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = [0x11_u8; 32];
//! let nonce = [0x22_u8; XNONCE_BYTES];
//! let params = Params::new(&key, &nonce, b"header");
//! let mut cipher = XChaCha20Poly1305::new();
//! cipher.init(CipherDirection::Encrypt, &params)?;
//!
//! let mut output = [0_u8; 23];
//! let mut written = cipher.process_bytes(b"message", &mut output)?;
//! written += cipher.do_final(&mut output[written..])?;
//! assert_eq!(written, output.len());
//! # Ok(())
//! # }
//! ```

#![no_std]

mod engine;
mod params;

pub use engine::{ChaCha20Poly1305, XChaCha20Poly1305};
pub use params::Params;

/// Secret-key length in bytes.
pub const KEY_BYTES: usize = 32;
/// RFC 8439 nonce length in bytes.
pub const NONCE_BYTES: usize = 12;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const XNONCE_BYTES: usize = 24;
/// Authentication-tag length in bytes.
pub const TAG_BYTES: usize = 16;
