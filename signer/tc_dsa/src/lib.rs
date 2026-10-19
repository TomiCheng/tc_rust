//! The DSA family's contracts, after Bouncy Castle's `IDsa`: a DSA signs the hash of a
//! message as a pair of integers (r, s), and verifies such a pair.

#![no_std]

mod traits;

pub use traits::{Dsa, DsaInit, DsaKCalculator};
