#![no_std]

//! X25519 與 X448 的型別安全 Diffie-Hellman 封裝。
//!
//! 實際運算全部轉交 [`tc_rfc7748`]；這個 crate 只負責區分私鑰、
//! 公鑰與 shared secret，避免誤用相同長度的 byte array。

pub mod x25519;
pub mod x448;
