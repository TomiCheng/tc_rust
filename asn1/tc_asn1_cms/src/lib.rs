#![no_std]

//! CMS (RFC 5652) structures, without signing, encryption or key agreement:
//!
//! - [`content`]: `ContentInfo`, the content types, and the certificate and
//!   revocation sets.
//! - [`signed`]: signers and how they name their certificates.
//! - [`recipient`]: recipients and how their keys are identified.
//! - [`params`]: the RFC 5084 AES-GCM and AES-CCM parameters.
//! - [`ecc`]: the RFC 5753 structures for elliptic-curve key agreement in CMS.
//! - [`tsd`]: RFC 5544 time-stamped data.

extern crate alloc;

pub mod content;
pub mod ecc;
#[cfg(test)]
mod fixtures;
pub mod params;
pub mod recipient;
pub mod signed;
pub mod tsd;
