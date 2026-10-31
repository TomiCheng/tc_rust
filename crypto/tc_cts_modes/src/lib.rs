//! 密文竊取（cipher text stealing），移植自 Bouncy Castle 的 `CtsBlockCipher`：以 ECB 或
//! CBC 加密任意長度、至少一個區塊的訊息，密文與明文等長。實作 `tc_buffered_cipher` 的
//! trait，直接持有 `tc_block_cipher` 的 block cipher。
//!
//! [`FixedCtsBlockCipher`] 的緩衝放在結構裡；開 `alloc` feature 才有 `CtsBlockCipher`，
//! 依執行期的區塊大小配置。串接方式由 [`Ecb`] 或 [`Cbc`] 選定。

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod chaining;
#[cfg(feature = "alloc")]
mod cts_block_cipher;
mod fixed_cts_block_cipher;
mod shared;

pub use chaining::{Cbc, CtsChaining, Ecb};
#[cfg(feature = "alloc")]
pub use cts_block_cipher::CtsBlockCipher;
pub use fixed_cts_block_cipher::FixedCtsBlockCipher;
