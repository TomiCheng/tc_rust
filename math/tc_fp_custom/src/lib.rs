#![no_std]

//! 每曲線特化的短 Weierstrass 質數曲線。
//!
//! 第一條概念驗證是 secp256r1：欄位採 bc 相同的八個 32-bit limb 與
//! Solinas 約簡，不經 Montgomery 表示；點與演算法仍實作 `tc_ec_core`
//! 的共通 trait。

extern crate alloc;
#[cfg(test)]
extern crate std;

mod secp256r1_curve;
mod secp256r1_field;
mod secp256r1_field_element;
mod secp256r1_point;

pub use secp256r1_curve::{SecP256R1Curve, secp256r1};
pub use secp256r1_field::SecP256R1Field;
pub use secp256r1_field_element::SecP256R1FieldElement;
pub use secp256r1_point::SecP256R1Point;

pub use tc_ec_core::{PointDecodeError, PointEncodeError};

#[cfg(test)]
mod tests;
