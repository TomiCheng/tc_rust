//! Key-wrapping algorithms ported from Bouncy Castle's `IWrapper` family.
//!
//! A key wrapper encrypts *key material* (rather than arbitrary plaintext) under
//! a key-encryption key, producing a slightly longer wrapped blob that carries
//! its own integrity check, so a tampered or wrong-key blob is rejected on
//! unwrap. Each algorithm builds on a block cipher from [`tc_block_cipher`] and
//! reports failures through this crate's own error type.

// 恆為 no_std；測試仍讓 `#[test]` 框架連結 std。
#![cfg_attr(not(test), no_std)]

// Wrap/Unwrap 會回傳新配置的位元組緩衝區，故整個 crate 為 no_std + alloc。
extern crate alloc;

pub mod dstu7624;
pub mod des_ede;
pub mod rfc3211;
pub mod rfc3394;
pub mod rfc5649;
mod wrap_error;

pub use dstu7624::{Dstu7624WrapEngine, Dstu7624WrapError};
pub use des_ede::{DesEdeWrapEngine, DesEdeWrapError, DesEdeWrapParams};
pub use rfc3211::{Rfc3211Params, Rfc3211WrapEngine};
pub use rfc3394::{Rfc3394Error, Rfc3394Params, Rfc3394WrapEngine};
pub use rfc5649::{Rfc5649Error, Rfc5649Params, Rfc5649WrapEngine};
pub use wrap_error::WrapError;

use tc_block_cipher::{AesEngine, AriaEngine, CamelliaEngine, SeedEngine};

/// AES Key Wrap (RFC 3394) — bc `AesWrapEngine`.
pub type AesWrapEngine = Rfc3394WrapEngine<AesEngine>;

/// ARIA Key Wrap (RFC 3394) — bc `AriaWrapEngine`.
pub type AriaWrapEngine = Rfc3394WrapEngine<AriaEngine>;

/// Camellia Key Wrap (RFC 3394) — bc `CamelliaWrapEngine`.
pub type CamelliaWrapEngine = Rfc3394WrapEngine<CamelliaEngine>;

/// SEED Key Wrap (RFC 3394) — bc `SeedWrapEngine`.
pub type SeedWrapEngine = Rfc3394WrapEngine<SeedEngine>;

/// AES Key Wrap with Padding (RFC 5649) — bc `AesWrapPadEngine`.
pub type AesWrapPadEngine = Rfc5649WrapEngine<AesEngine>;

/// ARIA Key Wrap with Padding (RFC 5649) — bc `AriaWrapPadEngine`.
pub type AriaWrapPadEngine = Rfc5649WrapEngine<AriaEngine>;
