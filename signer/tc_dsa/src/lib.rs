//! The DSA family's contracts, after Bouncy Castle's `IDsa`: a DSA signs the hash of a
//! message as a pair of integers (r, s), and verifies such a pair.

#![no_std]

extern crate alloc;

mod digest_signer;
mod digest_signer_error;
mod encoding;
mod encoding_error;
mod k_calculator;
mod traits;

pub use digest_signer::DsaDigestSigner;
pub use digest_signer_error::DsaDigestSignerError;
pub use encoding::{PlainDsaEncoding, StandardDsaEncoding};
pub use encoding_error::DsaEncodingError;
pub use k_calculator::{HMacDsaKCalculator, RandomDsaKCalculator};
pub use traits::{Dsa, DsaEncoding, DsaInit, DsaKCalculator};
