//! Deterministic random bit generators, after NIST SP 800-90A and Bouncy Castle's `SP80090Drbg`.
#![cfg_attr(feature = "drbg-hmac-sha256", doc = "")]
#![cfg_attr(feature = "drbg-hmac-sha256", doc = include_str!("../docs/Drbg.md"))]

mod algo;
mod default_drbg_provider;
mod drbg_entry;
mod drbg_provider;
mod drbg_trait;
mod empty_drbg_provider;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub use drbg_entry::DrbgEntry;
pub use drbg_provider::DrbgProvider;
pub use drbg_trait::Drbg;
pub(crate) use empty_drbg_provider::EmptyDrbgProvider;
