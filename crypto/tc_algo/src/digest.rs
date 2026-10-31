//! 依名稱或 OID 建立 digest，對應 BC 的 `DigestUtilities`。

#![allow(
    unused_variables,
    dead_code,
    unreachable_code,
    reason = "介面先建，實作還是 todo"
)]

mod algorithm;
mod any_digest;
mod dyn_digest;
mod entry;
mod functions;
mod helper;

pub use algorithm::Algorithm;
pub use any_digest::AnyDigest;
pub use entry::DigestEntry;
pub use functions::{algorithms, get, get_by_name, get_by_oid};
pub use helper::{
    calculate, calculate_by_name, calculate_by_name_into, calculate_by_oid, calculate_by_oid_into,
    calculate_into,
};
pub use tc_digest::{Digest, TryDigest};
