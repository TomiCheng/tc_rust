#![no_std]

//! RFC 7748 Montgomery-curve Diffie-Hellman。
//!
//! 這個 crate 目前提供 X25519；X448 之後可沿用同一層級加入。實作使用專用
//! Montgomery ladder 與固定寬度欄位運算，刻意不接短 Weierstrass 曲線使用的
//! `tc_ec_core` trait。

#[cfg(test)]
extern crate std;

pub mod x25519;
/// 提供後續 Ed25519 實作共用的內部欄位核心；可跨 crate 使用，但不承諾穩定 API。
#[doc(hidden)]
pub mod x25519_field;

pub use x25519::{
    POINT_SIZE, SCALAR_SIZE, calculate_agreement, clamp_private_key, generate_private_key,
    generate_public_key, scalar_mult, scalar_mult_base,
};
