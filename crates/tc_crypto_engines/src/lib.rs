//! Cryptographic engine implementations ported from Bouncy Castle.

// 關閉預設 feature 時為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(any(feature = "std", test)), no_std)]

// 部分 engine（目前 Threefish 的展開金鑰排程）使用 Vec，故整個 crate 為
// no_std + alloc；各 engine 仍可依需求使用固定陣列、擁有式或借用式資料。
extern crate alloc;

mod block_cipher_error;
mod cast_common;

pub mod aes;
pub mod aria;
pub mod blowfish;
pub mod camellia;
pub mod cast5;
pub mod cast6;
pub mod des;
pub mod des_ede;
pub mod dstu7624;
pub mod gost28147;
pub mod idea;
pub mod noekeon;
pub mod rc2;
pub mod rc5;
pub mod rc6;
pub mod rijndael;
pub mod seed;
pub mod serpent;
pub mod skipjack;
pub mod sm4;
pub mod tea;
pub mod threefish;
pub mod twofish;
pub mod xtea;

pub use aes::{AES_BLOCK_BYTES, AesEngine, AesLightEngine, AesParams};
pub use aria::{ARIA_BLOCK_BYTES, AriaEngine, AriaParams};
pub use blowfish::{
    BLOWFISH_BLOCK_BYTES, BLOWFISH_MAX_KEY_BYTES, BLOWFISH_MIN_KEY_BYTES, BlowfishEngine,
    BlowfishParams,
};
pub use block_cipher_error::BlockCipherError;
pub use camellia::{
    CAMELLIA_BLOCK_BYTES, CamelliaEngine, CamelliaLightEngine, CamelliaParams,
};
pub use cast5::{
    CAST5_BLOCK_BYTES, CAST5_MAX_KEY_BYTES, CAST5_MIN_KEY_BYTES, Cast5Engine,
    Cast5Params,
};
pub use cast6::{CAST6_BLOCK_BYTES, CAST6_KEY_BYTES, Cast6Engine, Cast6Params};
pub use des::{DES_BLOCK_BYTES, DES_KEY_BYTES, DesEngine, DesParams};
pub use des_ede::{
    DES_EDE_BLOCK_BYTES, DES_EDE_THREE_KEY_BYTES, DES_EDE_TWO_KEY_BYTES, DesEdeEngine,
    DesEdeParams,
};
pub use dstu7624::{
    DSTU7624_BLOCK_BITS, DSTU7624_KEY_BYTES, Dstu7624Engine, Dstu7624Params,
};
pub use gost28147::{
    GOST28147_BLOCK_BYTES, GOST28147_KEY_BYTES, GOST28147_S_BOX_BYTES, Gost28147Engine,
    Gost28147Params, Gost28147SBox,
};
pub use idea::{IDEA_BLOCK_BYTES, IDEA_KEY_BYTES, IdeaEngine, IdeaParams};
pub use noekeon::{
    NOEKEON_BLOCK_BYTES, NOEKEON_KEY_BYTES, NoekeonEngine, NoekeonParams,
};
pub use rc2::{
    RC2_BLOCK_BYTES, RC2_MAX_EFFECTIVE_KEY_BITS, RC2_MAX_KEY_BYTES, Rc2Engine, Rc2Params,
};
pub use rc5::{
    RC5_32_BLOCK_BYTES, RC5_64_BLOCK_BYTES, RC5_DEFAULT_ROUNDS, RC5_MAX_KEY_BYTES, RC5_MAX_ROUNDS,
    Rc5Params, Rc5Word, Rc532Engine, Rc564Engine,
};
pub use rc6::{RC6_BLOCK_BYTES, RC6_MAX_KEY_BYTES, RC6_ROUNDS, Rc6Engine, Rc6Params};
pub use rijndael::{
    RIJNDAEL_BLOCK_BITS, RIJNDAEL_KEY_BYTES, RijndaelEngine, RijndaelParams,
};
pub use seed::{SEED_BLOCK_BYTES, SEED_KEY_BYTES, SeedEngine, SeedParams};
pub use serpent::{
    SERPENT_BLOCK_BYTES, SERPENT_KEY_STEP_BYTES, SERPENT_MAX_KEY_BYTES, SERPENT_MIN_KEY_BYTES,
    SerpentEngine, SerpentParams, TnepresEngine,
};
pub use skipjack::{
    SKIPJACK_BLOCK_BYTES, SKIPJACK_KEY_BYTES, SkipjackEngine, SkipjackParams,
};
pub use sm4::{SM4_BLOCK_BYTES, SM4_KEY_BYTES, Sm4Engine, Sm4Params};
pub use tea::{TEA_BLOCK_BYTES, TEA_KEY_BYTES, TeaEngine, TeaParams};
pub use threefish::{ThreefishEngine, ThreefishParams};
pub use twofish::{
    TWOFISH_BLOCK_BYTES, TWOFISH_KEY_BYTES, TwofishEngine, TwofishParams,
};
pub use xtea::{XTEA_BLOCK_BYTES, XTEA_KEY_BYTES, XteaEngine, XteaParams};
