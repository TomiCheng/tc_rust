//! GOST R 34.10 的具名曲線，照 Bouncy Castle 的 `ECGost3410NamedCurves`：CryptoPro 的 2001
//! 版（RFC 4357）與 TC26 的 2012 版（RFC 7836）。十二個名稱共七組參數，別名與原曲線是同一組。
//! 都是質數體上的短 Weierstrass 曲線，以 `tc_fp_curve` 的通用運算建立。
//!
//! ```
//! use tc_gost_curves::TC26_GOST_3410_12_256_PARAMSET_A;
//!
//! // 曲線借用它的體，所以體由呼叫端保存
//! let named = TC26_GOST_3410_12_256_PARAMSET_A;
//! let field = named.field();
//! let curve = named.ct_curve(&field);
//! let g = named.ct_generator(&curve);
//! ```

#![no_std]

mod cryptopro;
mod gost_named_curve;
mod hex;
mod tc26;

pub use cryptopro::{
    GOSTR3410_2001_CRYPTOPRO_A, GOSTR3410_2001_CRYPTOPRO_B, GOSTR3410_2001_CRYPTOPRO_C,
    GOSTR3410_2001_CRYPTOPRO_XCHA, GOSTR3410_2001_CRYPTOPRO_XCHB,
};
pub use gost_named_curve::GostNamedCurve;
pub use tc26::{
    TC26_GOST_3410_12_256_PARAMSET_A, TC26_GOST_3410_12_256_PARAMSET_B,
    TC26_GOST_3410_12_256_PARAMSET_C, TC26_GOST_3410_12_256_PARAMSET_D,
    TC26_GOST_3410_12_512_PARAMSET_A, TC26_GOST_3410_12_512_PARAMSET_B,
    TC26_GOST_3410_12_512_PARAMSET_C,
};
