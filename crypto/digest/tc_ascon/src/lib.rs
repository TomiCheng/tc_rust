//! Ascon hash and extendable-output functions for the tc_rust workspace.

#![no_std]

extern crate alloc;

mod ascon_core;
pub mod ascon_cxof128;
pub mod ascon_hash256;
pub mod ascon_legacy;
pub mod ascon_xof128;
pub mod ascon_xof_legacy;

pub use ascon_cxof128::AsconCXof128;
pub use ascon_hash256::AsconHash256;
#[allow(deprecated)]
pub use ascon_legacy::{AsconDigest, AsconParameters};
#[allow(deprecated)]
pub use ascon_xof_legacy::{AsconXof, AsconXofParameters};
pub use ascon_xof128::AsconXof128;
