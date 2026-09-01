//! Ascon authenticated-encryption algorithms.
//!
//! [`aead128`] implements the finalized NIST SP 800-232 Ascon-AEAD128
//! algorithm. Legacy Ascon v1.2 variants will be exposed separately so they
//! cannot be confused with the finalized construction.

#![no_std]

pub mod aead128;
