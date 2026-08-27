//! Cryptographic engine implementations ported from Bouncy Castle.

// 關閉預設 feature 時為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// 部分 engine（目前為 Threefish）的參數型別擁有金鑰位元組（Vec），故整個
// crate 為 no_std + alloc；各 engine 仍可依需求使用擁有式或借用式參數。
extern crate alloc;

pub mod aes;
pub mod gost28147;
pub mod threefish;

pub use aes::{AES_BLOCK_BYTES, AesEngine, AesError, AesLightEngine, AesParams};
pub use gost28147::{
    GOST28147_BLOCK_BYTES, GOST28147_KEY_BYTES, GOST28147_S_BOX_BYTES, Gost28147Engine,
    Gost28147Error, Gost28147Params, Gost28147SBox,
};
pub use threefish::{ThreefishBlockSize, ThreefishEngine, ThreefishError, ThreefishParams};
