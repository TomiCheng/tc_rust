//! 中國 WAPI 的具名曲線 wapip192v1，照 Bouncy Castle 的 `GMNamedCurves`；同一張表的 sm2p256v1
//! 在 `tc_fp_custom`。質數體上的短 Weierstrass 曲線，以 `tc_fp_curve` 的通用運算建立。
//!
//! ```
//! use tc_wapi_curves::WAPIP192V1;
//!
//! // 曲線借用它的體，所以體由呼叫端保存
//! let field = WAPIP192V1.field();
//! let curve = WAPIP192V1.ct_curve(&field);
//! let g = WAPIP192V1.ct_generator(&curve);
//! ```

#![no_std]

mod hex;
mod wapi_named_curve;
mod wapip192v1;

pub use wapi_named_curve::WapiNamedCurve;
pub use wapip192v1::{WAPI192V1, WAPIP192V1};
