//! 未填充的原始 RSA 基元。
//!
//! 本 crate 只提供原始 RSA 運算，不包含 PKCS#1 v1.5、OAEP、PSS、盲簽章或金鑰產生；
//! 這些功能屬於其他層。本 crate 使用 `no_std` 與 `alloc`。
//!
//! # 核心引擎
//!
//! | 型別 | 整數表示法 | 私鑰 CRT 加速 |
//! | --- | --- | --- |
//! | [`FixedRsaCoreEngine<N>`] | 固定寬度 `FixedBigUint<N>` | 無 |
//! | [`HeapRsaCoreEngine`] | 堆配置 `BigUint` | 無 |
//! | [`FixedRsaCrtCoreEngine<N, H>`] | 固定寬度 `FixedBigUint<N>` | 有 |
//! | [`HeapRsaCrtCoreEngine`] | 堆配置 `BigUint` | 有 |
//!
//! 固定寬度版的容量由呼叫端指定 `N`，CRT 版另外要求 `N == 2 * H`；crate 本身沒有
//! 4096 位元的模數上限。堆版寬度由執行期的值決定，也不設模數上限，實際容量受可用
//! 記憶體限制。[`Rsa1024Core`]、[`Rsa2048CrtCore`] 等型別只是常用尺寸的便利別名。
//!
//! [`Rsa`] 是 [`AsymmetricBlockCipher`](tc_cipher::AsymmetricBlockCipher) 的子 trait：
//! 位元組入口與區塊大小由父 trait 提供，`Rsa` 額外提供輸入轉換、整數運算及輸出轉換。
//!
//! # 私鑰運算與計時防護
//!
//! 私鑰運算建議使用 [`RsaBlindedEngine`] 包住 CRT 核心，讓每次位元組運算都重新
//! 取樣盲化因子。直接呼叫 CRT 核心的 `process_block` 或 `process_int` 不含盲化。
//! CRT 核心也會用公開指數做 Lenstra 故障檢查，通過後才回傳結果。
//!
//! 固定排程的常數時間性質適用於固定寬度後端的私密指數運算；堆版的整數長度、
//! 模冪與模反元素運算隨數值變動，明確不保證常數時間，盲化也不會讓它變成固定排程。
//! 需要固定排程與盲化兩種防護時，請以固定寬度 CRT 核心搭配 `RsaBlindedEngine`。
//! 固定排程指數運算避免指數位元改變運算排程，每次重新取樣的 RSA 盲化則降低遠端
//! 計時及 Montgomery 額外約簡的可觀測性，兩者防護的問題不同，不能互相取代。
//!
//! # 金鑰參數與初始化
//!
//! [`RsaKeyRef`]、[`RsaPrivateCrtKeyRef`] 及其 owned 版本都是不驗證的大端序位元組
//! 容器，建構參數不代表金鑰有效。引擎透過 [`RsaInit::init`] 或 [`RsaCrtInit::init`]
//! 檢查模數、指數及 CRT 欄位的基本有效性；固定寬度版也會檢查數值是否放得進指定容量。
//! 這些基本檢查不等同完整的 RSA 金鑰驗證。

#![no_std]

extern crate alloc;

mod blinded_engine;
mod error;
mod params;
pub mod rsa_core;
pub mod rsa_crt;
pub mod traits;

pub use blinded_engine::RsaBlindedEngine;
pub use error::RsaError;
pub use params::{RsaKeyOwned, RsaKeyRef, RsaPrivateCrtKeyOwned, RsaPrivateCrtKeyRef};
pub use rsa_core::{
    FixedRsaCoreEngine, HeapRsaCoreEngine, Rsa1024Core, Rsa2048Core, Rsa3072Core, Rsa4096Core,
    limbs_for_bits,
};
pub use rsa_crt::{
    FixedRsaCrtCoreEngine, HeapRsaCrtCoreEngine, Rsa1024CrtCore, Rsa2048CrtCore, Rsa3072CrtCore,
    Rsa4096CrtCore,
};
pub use traits::{Rsa, RsaCrt, RsaCrtInit, RsaInit, RsaKeyParams, RsaPrivateCrtKeyParams};
