#![cfg_attr(feature = "hmac-sha256", doc = include_str!("../docs/Mac.md"))]

mod algo;
mod default_mac_provider;
mod empty_mac_provider;
mod mac_entry;
mod mac_provider;
mod mac_trait;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub(crate) use empty_mac_provider::EmptyMacProvider;
pub use mac_entry::MacEntry;
pub use mac_provider::MacProvider;
pub use mac_trait::Mac;
pub use tc_macs::MacInit;
