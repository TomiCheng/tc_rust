#![no_std]

//! Specialized short-Weierstrass SEC and SM2 prime curves.
//!
//! secp256r1 保留逐行移植的八個 32-bit limb 核心；其餘十一條 SEC 質數與 SM2
//! 曲線以靜態規格共用 u32-limb 骨架，並依質數選擇展開式、小補數或 Mersenne
//! Solinas 約簡。所有欄位都不經 Montgomery 表示，點與演算法仍實作
//! `tc_ec_core` 的共通 trait。

extern crate alloc;
#[cfg(test)]
extern crate std;

mod glv;
mod sec_curves;
mod secret_field;
pub use glv::SecP256K1Glv;
mod secp256r1_curve;
mod secp256r1_field;
mod secp256r1_field_element;
mod secp256r1_point;
mod specialized_curve;
mod specialized_field;
mod specialized_point;

pub use sec_curves::*;
pub use secp256r1_curve::{SecP256R1Curve, secp256r1};
pub use secp256r1_field::SecP256R1Field;
pub use secp256r1_field_element::SecP256R1FieldElement;
pub use secp256r1_point::SecP256R1Point;

pub use tc_ec_core::{PointDecodeError, PointEncodeError};

#[cfg(test)]
mod comparison_tests;
#[cfg(test)]
mod tests;
