#![cfg_attr(not(feature = "std"), no_std)]

//! Elliptic-curve and supporting finite-field foundations.
//!
//! Common EC types are re-exported at the crate root. The original module
//! hierarchy remains available through [`ec`].

// 本 crate 需要堆積配置（Vec/Box/String），但不一定需要完整 std。
// no_std 時仍透過 alloc 取得這些型別；std build 下 alloc 也可用（std 依賴 alloc）。
extern crate alloc;

pub mod binpoly;
pub mod ec;
pub mod raw;

pub use ec::{
    CoordinateSystem, F2mCurve, F2mFieldElement, F2mPoint, FpCurve, FpFieldElement, FpPoint,
    PointDecodeError,
};
