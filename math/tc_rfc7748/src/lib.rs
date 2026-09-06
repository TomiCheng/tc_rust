#![no_std]

//! RFC 7748 Montgomery-curve Diffie-Hellman。
//!
//! 這個 crate 提供 X25519 與 X448。實作使用專用
//! Montgomery ladder 與固定寬度欄位運算，刻意不接短 Weierstrass 曲線使用的
//! `tc_ec_core` trait。

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

pub use x25519::{
    POINT_SIZE, SCALAR_SIZE, calculate_agreement, clamp_private_key, generate_private_key,
    generate_public_key, precompute, scalar_mult, scalar_mult_base,
};
