//! Password-based key derivation for PBE, after Bouncy Castle's `PbeParametersGenerator`:
//! a password, a salt and an iteration count give a cipher key, optionally with an IV, or a
//! MAC key.
//!
//! The salt and the iteration count are public and travel with the ciphertext; only the
//! password is secret. A fresh random salt for each piece of data keeps an attacker from
//! precomputing one table for all of them, and the iteration count makes each guess slow.
//!
//! Protecting data with a password, with PBKDF2 over SHA-256, the scheme for new designs:
//!
//! ```
//! use tc_pbe::{PbeGenerator, PbeGeneratorInit, PbeParamsRef, Pkcs5S2};
//! use tc_pbe::pkcs5_password_to_utf8_bytes;
//! use tc_sha::Sha256Digest;
//!
//! // The password the user types, as UTF-8 bytes.
//! let password = pkcs5_password_to_utf8_bytes("correct horse battery staple");
//!
//! // When encrypting: a new random salt from a CSPRNG, stored with the ciphertext along with
//! // the iteration count. When decrypting: both read back from it.
//! let salt = [0x3c; 16];
//! // OWASP suggests 600,000 for PBKDF2-HMAC-SHA256; fewer here so the example runs quickly.
//! let iterations = 1_000;
//!
//! let mut pbkdf2 = Pkcs5S2::new(Sha256Digest::new());
//! pbkdf2.init(&PbeParamsRef::new(&password, &salt, iterations))?;
//!
//! // A key and IV for AES-256-CBC; the buffers set the lengths.
//! let mut key = [0u8; 32];
//! let mut iv = [0u8; 16];
//! pbkdf2.derive_key_and_iv(&mut key, &mut iv)?;
//! # Ok::<(), tc_pbe::PbeError>(())
//! ```
//!
//! The other schemes read formats that name them: [`Pkcs5S1`] for PBES1, [`Pkcs12`] for
//! `.p12` files and [`OpenSslPbe`] for old OpenSSL-encrypted PEM.

#![no_std]

extern crate alloc;

mod errors;
mod openssl_pbe;
mod params;
mod password;
mod pkcs12;
mod pkcs5_s1;
mod pkcs5_s2;
mod state;
mod traits;

pub use errors::PbeError;
pub use openssl_pbe::OpenSslPbe;
pub use params::{PbeParamsOwned, PbeParamsRef};
pub use password::{
    pkcs5_password_to_bytes, pkcs5_password_to_utf8_bytes, pkcs12_password_to_bytes,
};
pub use pkcs5_s1::Pkcs5S1;
pub use pkcs5_s2::Pkcs5S2;
pub use pkcs12::Pkcs12;
pub use traits::{PbeGenerator, PbeGeneratorInit, PbeParams};
