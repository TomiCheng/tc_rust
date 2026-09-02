//! Ascon authenticated-encryption algorithms.
//!
//! [`aead128`] implements the finalized NIST SP 800-232 Ascon-AEAD128
//! algorithm. [`legacy`] separately exposes the incompatible Ascon v1.2
//! Ascon-128, Ascon-128a, and Ascon-80pq algorithms.
//!
//! # Example
//!
//! `Params<'a>` borrows its key, nonce, and initial AAD without copying them:
//!
//! ```
//! use tc_ascon_aead::aead128::{Engine, KEY_BYTES, NONCE_BYTES, Params, TAG_BYTES};
//! use tc_cipher::{AeadCipher, AeadCipherInit, CipherDirection};
//!
//! let key = [0_u8; KEY_BYTES];
//! let nonce = [1_u8; NONCE_BYTES];
//! let aad = b"header";
//! let plaintext = b"message";
//! let params = Params::new(&key, &nonce, aad);
//!
//! let mut cipher = Engine::new();
//! cipher.init(CipherDirection::Encrypt, &params).unwrap();
//! let mut ciphertext_and_tag = [0_u8; 7 + TAG_BYTES];
//! let mut written = cipher
//!     .process_bytes(plaintext, &mut ciphertext_and_tag)
//!     .unwrap();
//! written += cipher
//!     .do_final(&mut ciphertext_and_tag[written..])
//!     .unwrap();
//! assert_eq!(written, ciphertext_and_tag.len());
//!
//! let mut decipher = Engine::new();
//! decipher
//!     .init(CipherDirection::Decrypt, &params)
//!     .unwrap();
//! let mut recovered = [0_u8; 7];
//! let mut recovered_len = decipher
//!     .process_bytes(&ciphertext_and_tag, &mut recovered)
//!     .unwrap();
//! recovered_len += decipher
//!     .do_final(&mut recovered[recovered_len..])
//!     .unwrap();
//! assert_eq!(recovered_len, plaintext.len());
//! assert_eq!(&recovered, plaintext);
//! ```

#![no_std]

pub mod aead128;
pub mod legacy;

mod params;

pub use params::Params;
