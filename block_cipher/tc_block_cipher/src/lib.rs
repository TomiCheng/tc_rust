//! Shared interfaces and key containers for single-block ciphers.
//!
//! This crate defines how to initialize a cipher and process a block; it does
//! not implement an encryption algorithm, mode, padding or authentication.
//! Use a concrete engine with these traits, and an authenticated-encryption
//! construction when protecting messages rather than individual blocks.
//!
//! # Using an engine
//!
//! Supply key material through [`KeyParams`], select a [`CipherDirection`],
//! and call [`BlockCipherInit::init`]. After successful initialization, use
//! [`BlockCipher::block_size`] to size buffers and
//! [`BlockCipher::process_block`] to transform one block.
//! Supported key lengths, additional parameters, timing guarantees and state
//! after a rejected initialization are defined by the concrete engine.
//!
//! # Choosing key storage
//!
//! - [`KeyRef`] borrows existing bytes without copying or wiping them.
//! - [`KeyFixed`] owns a fixed-size array and wipes its stored key on drop.
//! - `KeyOwned`, available with the `alloc` feature, takes ownership of a
//!   byte vector and wipes its stored key on drop.
//!
//! These containers do not validate algorithm-specific key lengths. Wiping an
//! owned container does not erase caller-held copies, engine key schedules or
//! every temporary copy. Callers must manage those lifetimes separately.
//!
//! # Features
//!
//! The crate is `no_std` and requires no allocator by default. Enable `alloc`
//! for `KeyOwned`; this does not require the standard library.
//!
//! [`InitError`] and [`BlockError`] are reusable error types. The traits use
//! associated error types so an engine may expose more specific failures.
//!
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod block_error;
mod cipher_direction;
mod init_error;
mod key;
mod traits;

pub use block_error::BlockError;
pub use cipher_direction::CipherDirection;
pub use init_error::InitError;
pub use key::*;
pub use traits::{BlockCipher, BlockCipherInit, KeyParams};
