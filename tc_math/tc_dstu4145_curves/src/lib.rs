//! 烏克蘭 DSTU 4145-2002 的具名曲線，照 Bouncy Castle 的 `Dstu4145NamedCurves`：GF(2^163) 到
//! GF(2^431) 的十條二元體曲線，BC 只以 OID 1.2.804.2.1.1.1.1.3.1.1.2.0 到 .9 稱呼，這裡以次數 m
//! 命名。以 `tc_f2m_curve` 的通用運算建立。
//!
//! ```
//! use tc_dstu4145_curves::DSTU4145_257;
//!
//! // 二元體的曲線自帶它的體
//! let curve = DSTU4145_257.ct_curve();
//! let g = DSTU4145_257.ct_generator(&curve);
//! ```

#![no_std]

mod dstu4145_named_curve;
mod hex;
mod named_curves;

pub use dstu4145_named_curve::Dstu4145NamedCurve;
pub use named_curves::{
    DSTU4145_163, DSTU4145_167, DSTU4145_173, DSTU4145_179, DSTU4145_191, DSTU4145_233,
    DSTU4145_257, DSTU4145_307, DSTU4145_367, DSTU4145_431,
};
