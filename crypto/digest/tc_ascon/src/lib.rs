//! Ascon 雜湊與 XOF（NIST SP 800-232 與舊版），以及同樣跑在 Ascon 置換函數上的 ISAP 雜湊，建在
//! `tc_digest` 的 trait 上。

#![no_std]

extern crate alloc;

mod ascon_core;
mod ascon_cxof128;
mod ascon_hash256;
mod ascon_legacy;
mod ascon_xof128;
mod ascon_xof_legacy;
mod isap;

pub use ascon_cxof128::AsconCXof128;
pub use ascon_hash256::AsconHash256;
#[allow(deprecated)]
pub use ascon_legacy::{AsconDigest, AsconParameters};
#[allow(deprecated)]
pub use ascon_xof_legacy::{AsconXof, AsconXofParameters};
pub use ascon_xof128::AsconXof128;
pub use isap::IsapDigest;
