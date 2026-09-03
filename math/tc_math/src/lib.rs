#![cfg_attr(not(feature = "std"), no_std)]

// 本 crate 需要堆積配置（Vec/Box/String），但不一定需要完整 std。
// no_std 時仍透過 alloc 取得這些型別；std build 下 alloc 也可用（std 依賴 alloc）。
extern crate alloc;

/// Compatibility re-exports for the arbitrary-precision integer API, whose
/// implementation now lives in the `tc_bigint` crate.
///
/// ```
/// use tc_math::big_integer::BigInteger;
///
/// assert_eq!(BigInteger::from_u32(2).pow(8), BigInteger::from_u32(256));
/// ```
pub mod big_integer {
    pub use tc_bigint::*;
}
pub mod binpoly;
pub mod ec;
pub mod raw;
