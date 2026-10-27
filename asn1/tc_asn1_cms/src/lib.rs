#![no_std]

//! CMS (RFC 5652) structures, without signing, encryption or key agreement:
//!
//! - [`content`]: `ContentInfo`, the content types, and the certificate and
//!   revocation sets.
//! - [`signed`]: signers and how they name their certificates.
//! - [`recipient`]: recipients and how their keys are identified.
//! - [`ecc`]: the RFC 5753 structures for elliptic-curve key agreement in CMS.

extern crate alloc;

pub mod content;
pub mod ecc;
#[cfg(test)]
mod fixtures;
pub mod recipient;
pub mod signed;
