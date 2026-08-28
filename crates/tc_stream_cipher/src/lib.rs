//! Stream cipher implementations ported from Bouncy Castle's engine package.
//!
//! All engines implement the [`StreamCipher`](tc_crypto_core::StreamCipher) trait
//! from `tc_crypto_core`. Each algorithm owns its parameter type (validated key,
//! and nonce where applicable) and reports failures through its own error type.
//!
//! Stream ciphers keep fixed-size keystream state, so this crate is `no_std`
//! with no `alloc` requirement.

// 關閉預設 feature 時為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(any(feature = "std", test)), no_std)]

pub mod chacha;
pub mod hc128;
pub mod hc256;
pub mod isaac;
pub mod rc4;
pub mod salsa20;
pub mod xsalsa20;

pub use chacha::{
    CHACHA_DEFAULT_ROUNDS, CHACHA_MAX_KEY_BYTES, CHACHA_MIN_KEY_BYTES, CHACHA_NONCE_BYTES,
    ChaChaEngine, ChaChaError, ChaChaParams,
};
pub use hc128::{HC128_IV_BYTES, HC128_KEY_BYTES, Hc128Engine, Hc128Error, Hc128Params};
pub use hc256::{
    HC256_IV_BYTES, HC256_KEY_BYTES, HC256_MIN_IV_BYTES, HC256_MIN_KEY_BYTES, Hc256Engine,
    Hc256Error, Hc256Params,
};
pub use isaac::{ISAAC_MAX_KEY_BYTES, IsaacEngine, IsaacError, IsaacParams};
pub use rc4::{RC4_MAX_KEY_BYTES, Rc4Engine, Rc4Error, Rc4Params};
pub use salsa20::{
    SALSA20_DEFAULT_ROUNDS, SALSA20_MAX_KEY_BYTES, SALSA20_MIN_KEY_BYTES, SALSA20_NONCE_BYTES,
    Salsa20Engine, Salsa20Error, Salsa20Params,
};
pub use xsalsa20::{XSALSA20_KEY_BYTES, XSALSA20_NONCE_BYTES, Xsalsa20Engine, Xsalsa20Params};
