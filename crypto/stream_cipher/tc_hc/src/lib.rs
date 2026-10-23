//! HC 系列串流 cipher：HC-128 與 HC-256，建在 `tc_stream_cipher` 的 trait 上。
//!
//! 兩者都以秘密狀態查表，不是常數時間；只為與 BC 相容保留，新的協定請用 ChaCha。

#![no_std]

mod hc128_engine;
mod hc256_engine;

pub use hc128_engine::Hc128Engine;
pub use hc256_engine::Hc256Engine;
