#![cfg_attr(feature = "shake256", doc = include_str!("../docs/Xof.md"))]

mod algo;
mod default_xof_provider;
mod empty_xof_provider;
mod xof_entry;
mod xof_provider;
mod xof_trait;

pub(crate) use algo::{BUILT_IN, CreateRows};
pub(crate) use empty_xof_provider::EmptyXofProvider;
pub use xof_entry::XofEntry;
pub use xof_provider::XofProvider;
pub use tc_digest::TryXof;
pub use xof_trait::Xof;
