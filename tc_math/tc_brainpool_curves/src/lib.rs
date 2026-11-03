//! Brainpool 的具名曲線，照 Bouncy Castle 的 `TeleTrusTNamedCurves`：RFC 5639 的 160 到 512
//! 位元，各有 r1 與 t1 兩條。t1 與同大小的 r1 同構，a = −3。都是質數體上的短 Weierstrass 曲線，
//! 以 `tc_fp_curve` 的通用運算建立。
//!
//! ```
//! use tc_brainpool_curves::BRAINPOOL_P256R1;
//!
//! // 曲線借用它的體，所以體由呼叫端保存
//! let field = BRAINPOOL_P256R1.field();
//! let curve = BRAINPOOL_P256R1.ct_curve(&field);
//! let g = BRAINPOOL_P256R1.ct_generator(&curve);
//! ```

#![no_std]

mod brainpool_named_curve;
mod hex;
mod r1;
mod t1;

pub use brainpool_named_curve::BrainpoolNamedCurve;
pub use r1::{
    BRAINPOOL_P160R1, BRAINPOOL_P192R1, BRAINPOOL_P224R1, BRAINPOOL_P256R1, BRAINPOOL_P320R1,
    BRAINPOOL_P384R1, BRAINPOOL_P512R1,
};
pub use t1::{
    BRAINPOOL_P160T1, BRAINPOOL_P192T1, BRAINPOOL_P224T1, BRAINPOOL_P256T1, BRAINPOOL_P320T1,
    BRAINPOOL_P384T1, BRAINPOOL_P512T1,
};
