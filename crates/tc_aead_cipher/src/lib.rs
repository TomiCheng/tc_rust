//! AEAD (authenticated encryption with associated data) ciphers, ported from
//! Bouncy Castle's `IAeadCipher` / `IAeadBlockCipher` family.
//!
//! An AEAD cipher encrypts a message and authenticates it together with
//! optional associated data, so decryption rejects a modified ciphertext, a
//! modified header, or the wrong key instead of returning unauthenticated
//! plaintext.
//!
//! **This crate is currently empty.** It holds the porting inventory only; see
//! the crate README for the catalogue of Bouncy Castle classes to be ported,
//! their underlying dependencies, and the planned order.

#![no_std]
