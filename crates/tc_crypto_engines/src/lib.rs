//! Cryptographic engine implementations ported from Bouncy Castle.

// 正常建置為 no_std;測試時放行 std,好讓 `#[test]` 框架連結(見 core/README)。
#![cfg_attr(not(test), no_std)]

// 參數型別擁有其金鑰位元組(Vec),故整個 crate 為 no_std + alloc。
extern crate alloc;

pub mod threefish;

pub use threefish::{ThreefishBlockSize, ThreefishEngine, ThreefishError, ThreefishParams};
