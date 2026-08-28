//! Cryptographic engine implementations ported from Bouncy Castle.

// 關閉預設 feature 時為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// 部分 engine（目前 Threefish 的展開金鑰排程）使用 Vec，故整個 crate 為
// no_std + alloc；各 engine 仍可依需求使用固定陣列、擁有式或借用式資料。
extern crate alloc;

pub mod aes;
pub mod aria;
pub mod blowfish;
pub mod camellia;
pub mod des;
pub mod des_ede;
pub mod gost28147;
pub mod threefish;

pub use aes::{AES_BLOCK_BYTES, AesEngine, AesError, AesLightEngine, AesParams};
pub use aria::{ARIA_BLOCK_BYTES, AriaEngine, AriaError, AriaParams};
pub use blowfish::{
    BLOWFISH_BLOCK_BYTES, BLOWFISH_MAX_KEY_BYTES, BLOWFISH_MIN_KEY_BYTES, BlowfishEngine,
    BlowfishError, BlowfishParams,
};
pub use camellia::{
    CAMELLIA_BLOCK_BYTES, CamelliaEngine, CamelliaError, CamelliaLightEngine, CamelliaParams,
};
pub use des::{DES_BLOCK_BYTES, DES_KEY_BYTES, DesEngine, DesError, DesParams};
pub use des_ede::{
    DES_EDE_BLOCK_BYTES, DES_EDE_THREE_KEY_BYTES, DES_EDE_TWO_KEY_BYTES, DesEdeEngine,
    DesEdeError, DesEdeParams,
};
pub use gost28147::{
    GOST28147_BLOCK_BYTES, GOST28147_KEY_BYTES, GOST28147_S_BOX_BYTES, Gost28147Engine,
    Gost28147Error, Gost28147Params, Gost28147SBox,
};
pub use threefish::{ThreefishEngine, ThreefishError, ThreefishParams};
