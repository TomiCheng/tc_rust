//! AEAD (authenticated encryption with associated data) ciphers, ported from
//! Bouncy Castle's `IAeadCipher` / `IAeadBlockCipher` family.
//!
//! An AEAD cipher encrypts a message and authenticates it together with
//! optional associated data, so decryption rejects a modified ciphertext, a
//! modified header, or the wrong key instead of returning unauthenticated
//! plaintext.
//!
//! The crate currently provides an allocation-free, incremental
//! [`ascon_aead128::Engine`] implementing the finalized NIST SP 800-232
//! Ascon-AEAD128 algorithm.

#![no_std]

pub mod ascon_aead128;
mod error;

pub use error::AeadCipherError;
