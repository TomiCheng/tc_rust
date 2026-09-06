#![no_std]

//! RFC 7748 Montgomery-curve Diffie-Hellman。
//!
//! 這個 crate 提供 X25519 與 X448。實作使用專用
//! Montgomery ladder 與固定寬度欄位運算，刻意不接短 Weierstrass 曲線使用的
//! `tc_ec_core` trait。
//!
//! 預設啟用 `std` 與 x86 runtime 分派；關閉 default features 時仍是純
//! `no_std`、無外部配置需求的 scalar 實作。

#[cfg(test)]
extern crate std;

mod ed25519_base;
pub mod x25519;
/// 提供後續 Ed25519 實作共用的內部欄位核心；可跨 crate 使用，但不承諾穩定 API。
#[doc(hidden)]
pub mod x25519_field;
pub mod x448;
/// X448 專用欄位核心；公開給後續 Ed448 實作共用，但不承諾穩定 API。
#[doc(hidden)]
pub mod x448_field;
