//! X9.62 的具名曲線中 SEC 2 沒有的那些，照 Bouncy Castle 的 `X962NamedCurves`：質數體上的
//! prime192v2、v3 與 prime239v1 到 v3，以 `tc_fp_curve` 建立；二元體上的 c2pnb 與 c2tnb，以
//! `tc_f2m_curve` 建立。prime192v1 與 prime256v1 就是 SEC 2 的 secp192r1 與 secp256r1，不在這裡。
//!
//! ```
//! use tc_x962_curves::{C2TNB239V1, PRIME239V1};
//!
//! // 質數體的曲線借用它的體，所以體由呼叫端保存
//! let field = PRIME239V1.field();
//! let curve = PRIME239V1.ct_curve(&field);
//! let g = PRIME239V1.ct_generator(&curve);
//!
//! // 二元體的曲線自帶它的體
//! let curve = C2TNB239V1.ct_curve();
//! let g = C2TNB239V1.ct_generator(&curve);
//! ```

#![no_std]

mod c2;
mod hex;
mod prime;
mod x962_f2m_named_curve;
mod x962_fp_named_curve;

pub use c2::{
    C2PNB163V1, C2PNB163V2, C2PNB163V3, C2PNB176W1, C2PNB208W1, C2PNB272W1, C2PNB304W1, C2PNB368W1,
    C2TNB191V1, C2TNB191V2, C2TNB191V3, C2TNB239V1, C2TNB239V2, C2TNB239V3, C2TNB359V1, C2TNB431R1,
};
pub use prime::{PRIME192V2, PRIME192V3, PRIME239V1, PRIME239V2, PRIME239V3};
pub use x962_f2m_named_curve::X962F2mNamedCurve;
pub use x962_fp_named_curve::X962FpNamedCurve;
