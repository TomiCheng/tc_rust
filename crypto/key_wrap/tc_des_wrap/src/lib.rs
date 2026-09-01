//! CMS Triple-DES key wrapping as specified by RFC 3217.

#![no_std]

extern crate alloc;

mod engine;

pub use engine::DesEdeWrapEngine;

/// CMS Triple-DES key-wrap operation error.
pub type DesEdeWrapError = tc_cipher::KeyWrapError<tc_cipher::BlockError>;
/// CMS Triple-DES key-wrapper initialization error.
pub type DesEdeWrapInitError = tc_cipher::KeyWrapInitError<tc_cipher::InitError>;
