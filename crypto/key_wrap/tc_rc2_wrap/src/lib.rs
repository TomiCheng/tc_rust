//! CMS RC2 key wrapping as specified by RFC 3217.

#![no_std]

extern crate alloc;

mod engine;

pub use engine::Rc2WrapEngine;

/// CMS RC2 key-wrap operation error.
pub type Rc2WrapError = tc_cipher::KeyWrapError<tc_cipher::BlockError>;
/// CMS RC2 key-wrapper initialization error.
pub type Rc2WrapInitError = tc_cipher::KeyWrapInitError<tc_cipher::InitError>;
