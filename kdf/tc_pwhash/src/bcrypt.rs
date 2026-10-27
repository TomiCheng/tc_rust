//! bcrypt, by Niels Provos and David Mazières: [`Bcrypt`] is the raw function, BC's `BCrypt`,
//! and [`OpenBsdBcrypt`] the `$2y$` hash strings of OpenBSD, BC's `OpenBsdBCrypt`.
//!
//! Storing a password and checking a login against it:
//!
//! ```
//! use tc_pwhash::bcrypt::OpenBsdBcrypt;
//!
//! // A fresh random salt for every password; the cost doubles the work per step.
//! let salt = [0x2f; 16];
//! let stored = OpenBsdBcrypt::generate(b"correct horse", &salt, 10)?;
//! assert!(stored.starts_with("$2y$10$"));
//!
//! // The string holds the version, cost and salt, so it is all a check needs.
//! assert!(OpenBsdBcrypt::check_password(&stored, b"correct horse")?);
//! assert!(!OpenBsdBcrypt::check_password(&stored, b"wrong horse")?);
//! # Ok::<(), tc_pwhash::bcrypt::BcryptError>(())
//! ```

mod base64;
mod bcrypt_error;
mod bcrypt_version;
mod eks_blowfish;
mod generator;
mod open_bsd_bcrypt;
mod tables;

pub use bcrypt_error::BcryptError;
pub use bcrypt_version::BcryptVersion;
pub use generator::Bcrypt;
pub use open_bsd_bcrypt::OpenBsdBcrypt;
