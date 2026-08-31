//! Message authentication code implementations ported from Bouncy Castle's
//! `Org.BouncyCastle.Crypto.Macs` namespace.
//!
//! Implementations in this crate use the [`Mac`](tc_crypto_core::Mac) and
//! [`MacInit`](tc_crypto_core::MacInit) traits from `tc_crypto_core`.

#![no_std]

pub mod poly1305;
