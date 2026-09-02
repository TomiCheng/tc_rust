//! DSTU 7624 KCCM authenticated encryption.
//!
//! KCCM is distinct from NIST CCM. It uses DSTU 7624's full-block nonce,
//! little-endian gamma counter, and `Nb` parameter.
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//! use tc_dstu7624::Engine128;
//! use tc_kccm::KccmBlockCipher;
//! use tc_params::AeadBlockParams;
//!
//! let key = [0x11_u8; 16];
//! let nonce = [0x22_u8; 16];
//! let aad = [0x33_u8; 16];
//! let params = AeadBlockParams::new(&key, &nonce, 16, &aad);
//! let mut encryptor = KccmBlockCipher::new(Engine128::new());
//! encryptor.init(CipherDirection::Encrypt, &params)?;
//! encryptor.process_bytes(&[0x44_u8; 16], &mut [])?;
//! let mut ciphertext = [0_u8; 16 + 16];
//! encryptor.do_final(&mut ciphertext)?;
//!
//! let mut decryptor = KccmBlockCipher::new(Engine128::new());
//! decryptor.init(CipherDirection::Decrypt, &params)?;
//! decryptor.process_bytes(&ciphertext, &mut [])?;
//! let mut plaintext = [0_u8; 16];
//! decryptor.do_final(&mut plaintext)?;
//! assert_eq!(plaintext, [0x44; 16]);
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
pub use engine::KccmBlockCipher;

/// Smallest KCCM authentication-tag size in bytes.
pub const MIN_MAC_BYTES: usize = 8;
/// Largest KCCM authentication-tag size in bytes.
pub const MAX_MAC_BYTES: usize = 64;
