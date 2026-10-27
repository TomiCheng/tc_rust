//! Password hashing schemes, after Bouncy Castle: deliberately slow functions that turn a
//! password and a salt into a hash to store and later check a password against, or into a key.
//!
//! Each scheme is a feature and a module of its own:
//!
//! - [`argon2`] (`argon2`): Argon2d, Argon2i and Argon2id of RFC 9106, memory-hard.
//! - [`bcrypt`] (`bcrypt`): bcrypt, raw and as OpenBSD's `$2y$` hash strings.
//! - [`scrypt`] (`scrypt`): scrypt of RFC 7914, memory-hard.

#![no_std]

extern crate alloc;

#[cfg(feature = "argon2")]
pub mod argon2;
#[cfg(feature = "bcrypt")]
pub mod bcrypt;
#[cfg(feature = "scrypt")]
pub mod scrypt;
