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
//! 三個實作都實作 `rand_core::TryRng<Error = DrbgError>` 與
//! `rand_core::TryCryptoRng`。需要重新植入時回傳 [`DrbgError::ReseedRequired`]，
//! 由呼叫端決定要重新植入還是放棄。單次請求上限是 32 KiB（2^18 bits，同 Bouncy
//! Castle），超過時 panic，呼叫前檢查長度即可避免。需要 `CryptoRng` 的地方，用
//! `rand_core::UnwrapErr` 包起來，錯誤會改成 panic。
//!
//! 內部狀態含有秘密資料，但本 crate 不保證編譯器會抹除已被覆寫或釋放的記憶體。
//!
//! # 範例
//!
//! ```
//! use rand_core::{Rng, TryRng, UnwrapErr};
//! use tc_aes::AesEngine;
//! use tc_drbg::{CtrDrbg, Drbg, HashDrbg, HmacDrbg};
//! use tc_macs::Hmac;
//! use tc_sha::Sha256Digest;
//!
//! // 熵來源由呼叫端提供；這裡用作業系統的亂數
//! let mut entropy = rand::rng();
//!
//! // HMAC_DRBG：安全強度 256 bits，每次從熵來源讀 32 bytes，再給 nonce 與 personalization
//! let mut drbg = HmacDrbg::new(
//!     Hmac::new(Sha256Digest::new()),
//!     256,
//!     32,
//!     &mut entropy,
//!     b"a 16-byte nonce!",
//!     b"my app v1",
//! )?;
//!
//! let mut key = [0_u8; 32];
//! drbg.generate(&mut key, &[])?;
//!
//! // 需要 prediction resistance 時，先 reseed 再產生；也可以混入額外輸入
//! drbg.reseed(&mut entropy, &[])?;
//! drbg.generate(&mut key, b"additional input")?;
//!
//! // 也能當成 rand_core 的亂數來源；需要重新植入時回傳錯誤
//! let _ = drbg.try_next_u64()?;
//!
//! // 交給需要 CryptoRng 的函式時，用 UnwrapErr 把錯誤改成 panic
//! let _ = UnwrapErr(&mut drbg).next_u64();
//!
//! // Hash_DRBG 與 CTR_DRBG 的建立方式相同，只是換掉底層元件
//! let mut hash = HashDrbg::new(Sha256Digest::new(), 256, 32, &mut entropy, b"nonce", &[])?;
//! hash.generate(&mut key, &[])?;
//!
//! // CTR_DRBG 另外指定 AES 金鑰長度（bits），並選擇要不要用 derivation function
//! let mut ctr = CtrDrbg::new_with_derivation_function(
//!     AesEngine::new(),
//!     256,
//!     256,
//!     32,
//!     &mut entropy,
//!     b"nonce",
//!     &[],
//! )?;
//! ctr.generate(&mut key, &[])?;
//! # Ok::<(), tc_drbg::DrbgError>(())
//! ```

extern crate alloc;

mod ctr_drbg;
mod derivation;
mod drbg;
mod errors;
mod hash_drbg;
mod hmac_drbg;
mod traits;

pub use ctr_drbg::CtrDrbg;
pub use errors::DrbgError;
pub use hash_drbg::HashDrbg;
pub use hmac_drbg::HmacDrbg;
pub use traits::Drbg;
