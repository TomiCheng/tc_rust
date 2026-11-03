//! 法國 ANSSI 的具名曲線 FRP256v1，照 Bouncy Castle 的 `ANSSINamedCurves`。質數體上的短
//! Weierstrass 曲線，以 `tc_fp_curve` 的通用運算建立。
//!
//! ```
//! use tc_anssi_curves::FRP256V1;
//!
//! // 曲線借用它的體，所以體由呼叫端保存
//! let field = FRP256V1.field();
//! let curve = FRP256V1.ct_curve(&field);
//! let g = FRP256V1.ct_generator(&curve);
//! ```

#![no_std]

mod anssi_named_curve;
mod frp256v1;
mod hex;

pub use anssi_named_curve::AnssiNamedCurve;
pub use frp256v1::FRP256V1;
