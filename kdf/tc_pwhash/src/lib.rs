//! Password hashing schemes, after Bouncy Castle: deliberately slow functions that turn a
//! password and a salt into a hash to store and later check a password against, or into a key.
//!
//! Each scheme is a module of its own:
//!
//! - [`argon2`]: Argon2d, Argon2i and Argon2id of RFC 9106, memory-hard.
//! - [`bcrypt`]: bcrypt, raw and as OpenBSD's `$2y$` hash strings.
//! - [`scrypt`]: scrypt of RFC 7914, memory-hard.
//!
//! Storing a password at sign-up and checking it at login, with Argon2id:
//!
//! ```
//! use tc_constant_time::fixed_time_eq;
//! use tc_pwhash::argon2::{Argon2, Argon2ParamsRef, Argon2Type};
//!
//! // Sign-up: a fresh random salt, kept with the account along with the parameters and hash.
//! let salt = [0x3c; 16];
//! let params = Argon2ParamsRef::new(Argon2Type::Argon2id, &salt)
//!     .with_iterations(3)
//!     .with_memory_kib(64 * 1024)
//!     .with_parallelism(4);
//! let mut argon2 = Argon2::new();
//! argon2.init(&params)?;
//! let mut stored = [0u8; 32];
//! argon2.generate_bytes(b"correct horse", &mut stored)?;
//!
//! // Login: hash the attempt under the same salt and parameters, and compare in constant time.
//! let mut attempt = [0u8; 32];
//! argon2.generate_bytes(b"correct horse", &mut attempt)?;
//! assert!(fixed_time_eq(&stored, &attempt));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [`bcrypt::OpenBsdBcrypt`] instead keeps the salt and cost in one string and does the check.

#![no_std]

extern crate alloc;

pub mod argon2;
pub mod bcrypt;
pub mod scrypt;
