//! Salsa20 與 XSalsa20 串流 cipher，建在 `tc_stream_cipher` 的 trait 上。
//!
//! 兩者都是 ARX 結構（32 位元加法、旋轉、XOR），常數時間。新的協定請優先考慮 ChaCha，它是
//! Salsa20 的後繼設計。

#![no_std]

mod salsa;
mod salsa20_engine;
mod xsalsa20_engine;

pub use salsa20_engine::Salsa20Engine;
pub use xsalsa20_engine::Xsalsa20Engine;
