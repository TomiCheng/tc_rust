#![no_std]

//! CMS structures, without signing, encryption or key agreement:
//!
//! - [`ecc`]: the RFC 5753 structures for elliptic-curve key agreement in CMS.

extern crate alloc;

pub mod ecc;
