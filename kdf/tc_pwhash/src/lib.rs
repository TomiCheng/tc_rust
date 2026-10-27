//! Password hashing schemes, after Bouncy Castle: deliberately slow functions that turn a
//! password and a salt into a hash to store and later check a password against, or into a key.
//!
//! Each scheme is a feature and a module of its own:
//!
//! - [`bcrypt`] (`bcrypt`): bcrypt, raw and as OpenBSD's `$2y$` hash strings.
//! - [`scrypt`] (`scrypt`): scrypt of RFC 7914, memory-hard.

#![no_std]

extern crate alloc;

#[cfg(feature = "bcrypt")]
pub mod bcrypt;
#[cfg(feature = "scrypt")]
pub mod scrypt;
