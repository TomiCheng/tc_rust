#![no_std]

//! NIST SP 800-90A 的決定性隨機位元產生器。
//!
//! 本 crate 提供 HMAC_DRBG、Hash_DRBG 與僅限 AES 的 CTR_DRBG。熵不會在
//! crate 內自行向作業系統取得；建立實例與重新植入時都由呼叫端傳入
//! [`rand_core::CryptoRng`]。
//!
//! 介面沒有 `prediction_resistant` 旗標。需要 prediction resistance 的呼叫端
//! 應先呼叫 [`Drbg::reseed`]，再呼叫 [`Drbg::generate`]。
//!
//! 三個實作都實作 `rand_core::TryRng<Error = Infallible>` 與
//! `rand_core::TryCryptoRng`，因此會透過 rand_core 0.10 的 blanket impl 取得
//! `Rng`、`RngCore` 與 `CryptoRng`。`Rng::fill_bytes` 無法回傳錯誤，所以當重新
//! 植入已成為必要條件或單次請求過大時會 panic；需要處理錯誤的呼叫端應直接使用
//! [`Drbg::generate`]。
//!
//! 內部狀態含有秘密資料，但本 crate 不保證編譯器會抹除已被覆寫或釋放的記憶體。

extern crate alloc;

mod ctr_drbg;
mod derivation;
mod drbg;
mod hash_drbg;
mod hmac_drbg;

pub use ctr_drbg::CtrDrbg;
pub use drbg::{Drbg, DrbgError};
pub use hash_drbg::HashDrbg;
pub use hmac_drbg::HmacDrbg;
