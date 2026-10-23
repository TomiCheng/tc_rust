//! Salsa20 與 XSalsa20 串流 cipher，建在 `tc_stream_cipher` 的 trait 上。
//!
//! 兩者都是 ARX 結構（32 位元加法、旋轉、XOR），常數時間。新的協定請優先考慮 ChaCha，它是
//! Salsa20 的後繼設計。
//!
//! [`Salsa20Engine`] 與 [`Xsalsa20Engine`] 自行挑後端：開了 `rustcrypto` 時，RustCrypto 涵蓋的長度與
//! 回合數交給 `salsa20` crate，其餘留在 portable 實作；開不開 feature 接受的參數都一樣。各後端也可以
//! 直接使用。

#![no_std]

#[cfg(feature = "rustcrypto")]
mod rustcrypto_engine;
mod salsa;
mod salsa20_engine;
mod salsa20_portable_engine;
mod xsalsa20_engine;
mod xsalsa20_portable_engine;

#[cfg(feature = "rustcrypto")]
pub use rustcrypto_engine::{Salsa20RustCryptoEngine, Xsalsa20RustCryptoEngine};
pub use salsa20_engine::Salsa20Engine;
pub use salsa20_portable_engine::Salsa20PortableEngine;
pub use xsalsa20_engine::Xsalsa20Engine;
pub use xsalsa20_portable_engine::Xsalsa20PortableEngine;
